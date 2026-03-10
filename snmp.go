package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// snmpDefaultPort is the standard SNMP agent port.
const snmpDefaultPort = 161

// snmpMaxOIDs is the maximum number of OIDs allowed in a single poll.
const snmpMaxOIDs = 64

// validOIDRe matches dotted-decimal SNMP OIDs like "1.3.6.1.2.1.1.3.0".
// OIDs must start with a digit, contain only digits and dots, and not end with a dot.
var validOIDPattern = func(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	prevDot := true // treat start as "after dot" to reject leading dot
	for _, c := range s {
		if c == '.' {
			if prevDot {
				return false // leading dot or double dot
			}
			prevDot = true
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		prevDot = false
	}
	// Must not end with dot and must contain at least one dot
	return !prevDot && strings.Contains(s, ".")
}

// checkSNMP performs an SNMP poll against the target device.
//
// Metadata fields read (input):
//
//	"version":          "2c" or "3" (default: "2c")
//	"community":        SNMP community string (v2c, default: "public")
//	"port":             UDP port (default: "161")
//	"oid":              single OID to query (e.g. "1.3.6.1.2.1.1.3.0")
//	"oids":             comma-separated OIDs for bulk poll
//	"operation":        "get" (default), "walk", "bulk"
//
// SNMPv3 fields:
//
//	"security_level":   "noAuthNoPriv", "authNoPriv", "authPriv"
//	"username":         USM username
//	"auth_protocol":    "MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"
//	"auth_password":    authentication passphrase
//	"privacy_protocol": "DES", "AES", "AES192", "AES256", "AES192C", "AES256C"
//	"privacy_password": privacy passphrase
//
// Metadata fields returned (output):
//
//	"snmp_value":       value of queried OID (single GET)
//	"snmp_type":        ASN.1 type name
//	"snmp_results":     pipe-separated "oid=value" pairs (bulk/walk)
//	"snmp_count":       number of results returned
func (t *Task) checkSNMP(ctx context.Context) (status, errMsg string, metadata map[string]string) {
	meta := t.payload.Metadata
	target := t.payload.Target

	// Parse port
	port := snmpDefaultPort
	if portStr := meta["port"]; portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return StatusError, fmt.Sprintf("invalid SNMP port: %s", portStr), nil
		}
		port = p
	}

	// Parse and validate OIDs
	operation := meta["operation"]
	if operation == "" {
		operation = "get"
	}

	oids, err := parseSNMPOIDs(meta["oid"], meta["oids"])
	if err != nil {
		return StatusError, err.Error(), nil
	}
	if len(oids) == 0 {
		return StatusError, "no OID specified: set 'oid' or 'oids' in metadata", nil
	}

	// Build gosnmp client
	client := &gosnmp.GoSNMP{
		Target:  target,
		Port:    uint16(port),
		Timeout: time.Duration(t.payload.Timeout) * time.Second,
		Retries: 1,
		Logger:  gosnmp.NewLogger(&snmpSlogAdapter{logger: t.logger}),
	}

	// Configure version and auth
	version := meta["version"]
	if version == "" {
		version = "2c"
	}

	switch version {
	case "2c":
		client.Version = gosnmp.Version2c
		community := meta["community"]
		if community == "" {
			community = "public"
		}
		client.Community = community

	case "3":
		client.Version = gosnmp.Version3
		if err := configureSNMPv3(client, meta); err != nil {
			return StatusError, err.Error(), nil
		}

	default:
		return StatusError, fmt.Sprintf("unsupported SNMP version: %s (use '2c' or '3')", version), nil
	}

	// Connect
	if err := client.ConnectIPv4(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return StatusTimeout, "SNMP connection timed out", nil
		}
		return StatusDown, fmt.Sprintf("SNMP connect failed: %s", err.Error()), nil
	}
	defer client.Conn.Close()

	// Execute operation
	switch operation {
	case "get":
		return t.snmpGet(client, oids)
	case "walk":
		if len(oids) > 1 {
			return StatusError, "walk supports only a single OID prefix", nil
		}
		return t.snmpWalk(client, oids[0])
	case "bulk":
		return t.snmpBulkGet(client, oids)
	default:
		return StatusError, fmt.Sprintf("unsupported SNMP operation: %s (use 'get', 'walk', or 'bulk')", operation), nil
	}
}

// snmpGet performs an SNMP GET for one or more OIDs.
func (t *Task) snmpGet(client *gosnmp.GoSNMP, oids []string) (status, errMsg string, metadata map[string]string) {
	result, err := client.Get(oids)
	if err != nil {
		return StatusDown, fmt.Sprintf("SNMP GET failed: %s", err.Error()), nil
	}

	if result.Error != gosnmp.NoError {
		return StatusDown, fmt.Sprintf("SNMP error: %s", result.Error.String()), nil
	}

	metadata = make(map[string]string)

	if len(result.Variables) == 1 {
		// Single OID — return as snmp_value
		pdu := result.Variables[0]
		if pdu.Type == gosnmp.NoSuchObject || pdu.Type == gosnmp.NoSuchInstance {
			return StatusDown, fmt.Sprintf("OID %s: no such object/instance", pdu.Name), nil
		}
		metadata["snmp_value"] = formatSNMPValue(pdu)
		metadata["snmp_type"] = pdu.Type.String()
		metadata["snmp_oid"] = pdu.Name
	} else {
		// Multiple OIDs — return as pipe-separated pairs
		var pairs []string
		for _, pdu := range result.Variables {
			if pdu.Type == gosnmp.NoSuchObject || pdu.Type == gosnmp.NoSuchInstance {
				pairs = append(pairs, fmt.Sprintf("%s=NoSuchObject", pdu.Name))
				continue
			}
			pairs = append(pairs, fmt.Sprintf("%s=%s", pdu.Name, formatSNMPValue(pdu)))
		}
		metadata["snmp_results"] = strings.Join(pairs, "|")
		metadata["snmp_count"] = strconv.Itoa(len(result.Variables))
	}

	return StatusUp, "", metadata
}

// snmpWalk performs an SNMP Walk on a subtree.
func (t *Task) snmpWalk(client *gosnmp.GoSNMP, rootOID string) (status, errMsg string, metadata map[string]string) {
	var results []gosnmp.SnmpPDU

	var walkErr error
	if client.Version == gosnmp.Version1 {
		walkErr = client.Walk(rootOID, func(pdu gosnmp.SnmpPDU) error {
			results = append(results, pdu)
			if len(results) > 1000 {
				return fmt.Errorf("walk result limit exceeded (1000 entries)")
			}
			return nil
		})
	} else {
		walkErr = client.BulkWalk(rootOID, func(pdu gosnmp.SnmpPDU) error {
			results = append(results, pdu)
			if len(results) > 1000 {
				return fmt.Errorf("walk result limit exceeded (1000 entries)")
			}
			return nil
		})
	}

	if walkErr != nil {
		// If we got partial results before the error, still report them
		if len(results) == 0 {
			return StatusDown, fmt.Sprintf("SNMP walk failed: %s", walkErr.Error()), nil
		}
	}

	if len(results) == 0 {
		return StatusDown, fmt.Sprintf("SNMP walk returned no results for OID %s", rootOID), nil
	}

	metadata = make(map[string]string)
	var pairs []string
	for _, pdu := range results {
		pairs = append(pairs, fmt.Sprintf("%s=%s", pdu.Name, formatSNMPValue(pdu)))
	}
	metadata["snmp_results"] = strings.Join(pairs, "|")
	metadata["snmp_count"] = strconv.Itoa(len(results))

	return StatusUp, "", metadata
}

// snmpBulkGet performs an SNMP GETBULK operation.
func (t *Task) snmpBulkGet(client *gosnmp.GoSNMP, oids []string) (status, errMsg string, metadata map[string]string) {
	if client.Version == gosnmp.Version1 {
		return StatusError, "SNMP GETBULK not supported with SNMPv1", nil
	}

	result, err := client.GetBulk(oids, 0, 25) // non-repeaters=0, max-repetitions=25
	if err != nil {
		return StatusDown, fmt.Sprintf("SNMP GETBULK failed: %s", err.Error()), nil
	}

	if result.Error != gosnmp.NoError {
		return StatusDown, fmt.Sprintf("SNMP error: %s", result.Error.String()), nil
	}

	metadata = make(map[string]string)
	var pairs []string
	for _, pdu := range result.Variables {
		if pdu.Type == gosnmp.EndOfMibView || pdu.Type == gosnmp.NoSuchObject || pdu.Type == gosnmp.NoSuchInstance {
			continue
		}
		pairs = append(pairs, fmt.Sprintf("%s=%s", pdu.Name, formatSNMPValue(pdu)))
	}
	metadata["snmp_results"] = strings.Join(pairs, "|")
	metadata["snmp_count"] = strconv.Itoa(len(pairs))

	if len(pairs) == 0 {
		return StatusDown, "SNMP GETBULK returned no results", nil
	}

	return StatusUp, "", metadata
}

// configureSNMPv3 sets up USM security parameters for SNMPv3.
func configureSNMPv3(client *gosnmp.GoSNMP, meta map[string]string) error {
	username := meta["username"]
	if username == "" {
		return fmt.Errorf("SNMPv3 requires 'username' in metadata")
	}

	client.SecurityModel = gosnmp.UserSecurityModel
	usmParams := &gosnmp.UsmSecurityParameters{
		UserName: username,
	}

	secLevel := meta["security_level"]
	if secLevel == "" {
		secLevel = "authNoPriv"
	}

	switch secLevel {
	case "noAuthNoPriv":
		client.MsgFlags = gosnmp.NoAuthNoPriv

	case "authNoPriv":
		client.MsgFlags = gosnmp.AuthNoPriv
		authProto, err := parseSNMPAuthProtocol(meta["auth_protocol"])
		if err != nil {
			return err
		}
		usmParams.AuthenticationProtocol = authProto
		usmParams.AuthenticationPassphrase = meta["auth_password"]
		if usmParams.AuthenticationPassphrase == "" {
			return fmt.Errorf("SNMPv3 authNoPriv requires 'auth_password'")
		}

	case "authPriv":
		client.MsgFlags = gosnmp.AuthPriv
		authProto, err := parseSNMPAuthProtocol(meta["auth_protocol"])
		if err != nil {
			return err
		}
		usmParams.AuthenticationProtocol = authProto
		usmParams.AuthenticationPassphrase = meta["auth_password"]
		if usmParams.AuthenticationPassphrase == "" {
			return fmt.Errorf("SNMPv3 authPriv requires 'auth_password'")
		}

		privProto, err := parseSNMPPrivProtocol(meta["privacy_protocol"])
		if err != nil {
			return err
		}
		usmParams.PrivacyProtocol = privProto
		usmParams.PrivacyPassphrase = meta["privacy_password"]
		if usmParams.PrivacyPassphrase == "" {
			return fmt.Errorf("SNMPv3 authPriv requires 'privacy_password'")
		}

	default:
		return fmt.Errorf("unsupported security_level: %s (use noAuthNoPriv, authNoPriv, authPriv)", secLevel)
	}

	client.SecurityParameters = usmParams
	return nil
}

// parseSNMPAuthProtocol converts a string to gosnmp auth protocol.
func parseSNMPAuthProtocol(s string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch strings.ToUpper(s) {
	case "MD5", "":
		return gosnmp.MD5, nil
	case "SHA":
		return gosnmp.SHA, nil
	case "SHA224":
		return gosnmp.SHA224, nil
	case "SHA256":
		return gosnmp.SHA256, nil
	case "SHA384":
		return gosnmp.SHA384, nil
	case "SHA512":
		return gosnmp.SHA512, nil
	default:
		return gosnmp.NoAuth, fmt.Errorf("unsupported auth_protocol: %s (use MD5, SHA, SHA224, SHA256, SHA384, SHA512)", s)
	}
}

// parseSNMPPrivProtocol converts a string to gosnmp privacy protocol.
func parseSNMPPrivProtocol(s string) (gosnmp.SnmpV3PrivProtocol, error) {
	switch strings.ToUpper(s) {
	case "DES", "":
		return gosnmp.DES, nil
	case "AES":
		return gosnmp.AES, nil
	case "AES192":
		return gosnmp.AES192, nil
	case "AES256":
		return gosnmp.AES256, nil
	case "AES192C":
		return gosnmp.AES192C, nil
	case "AES256C":
		return gosnmp.AES256C, nil
	default:
		return gosnmp.NoPriv, fmt.Errorf("unsupported privacy_protocol: %s (use DES, AES, AES192, AES256, AES192C, AES256C)", s)
	}
}

// parseSNMPOIDs parses and validates OIDs from single and CSV metadata fields.
func parseSNMPOIDs(single, csv string) ([]string, error) {
	var oids []string

	if single != "" {
		oid := strings.TrimSpace(single)
		if !validOIDPattern(oid) {
			return nil, fmt.Errorf("invalid OID format: %s", oid)
		}
		oids = append(oids, oid)
	}

	if csv != "" {
		for _, part := range strings.Split(csv, ",") {
			oid := strings.TrimSpace(part)
			if oid == "" {
				continue
			}
			if !validOIDPattern(oid) {
				return nil, fmt.Errorf("invalid OID format: %s", oid)
			}
			oids = append(oids, oid)
		}
	}

	if len(oids) > snmpMaxOIDs {
		return nil, fmt.Errorf("too many OIDs: %d (max %d)", len(oids), snmpMaxOIDs)
	}

	// Deduplicate while preserving order
	seen := make(map[string]bool, len(oids))
	unique := make([]string, 0, len(oids))
	for _, oid := range oids {
		if !seen[oid] {
			seen[oid] = true
			unique = append(unique, oid)
		}
	}

	return unique, nil
}

// formatSNMPValue converts an SNMP PDU value to a human-readable string.
func formatSNMPValue(pdu gosnmp.SnmpPDU) string {
	switch pdu.Type {
	case gosnmp.OctetString:
		b, ok := pdu.Value.([]byte)
		if !ok {
			return fmt.Sprintf("%v", pdu.Value)
		}
		// Check if it's printable ASCII
		if isPrintableASCII(b) {
			return string(b)
		}
		// Format as hex for non-printable (e.g. MAC addresses)
		return formatHexString(b)

	case gosnmp.ObjectIdentifier:
		return fmt.Sprintf("%v", pdu.Value)

	case gosnmp.TimeTicks:
		// TimeTicks are hundredths of a second
		ticks, ok := pdu.Value.(uint32)
		if !ok {
			return fmt.Sprintf("%v", pdu.Value)
		}
		d := time.Duration(ticks) * time.Millisecond * 10
		days := int(d.Hours()) / 24
		hours := int(d.Hours()) % 24
		mins := int(d.Minutes()) % 60
		secs := int(d.Seconds()) % 60
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, mins, secs)

	case gosnmp.Counter32, gosnmp.Counter64, gosnmp.Gauge32, gosnmp.Integer, gosnmp.Uinteger32:
		return fmt.Sprintf("%d", gosnmp.ToBigInt(pdu.Value).Int64())

	case gosnmp.IPAddress:
		return fmt.Sprintf("%s", pdu.Value)

	case gosnmp.Null, gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
		return ""

	default:
		return fmt.Sprintf("%v", pdu.Value)
	}
}

// isPrintableASCII returns true if all bytes are printable ASCII (0x20-0x7E) or common whitespace.
func isPrintableASCII(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7E {
			if c != '\t' && c != '\n' && c != '\r' {
				return false
			}
		}
	}
	return true
}

// formatHexString formats bytes as colon-separated hex (e.g. "00:1A:2B:3C:4D:5E").
func formatHexString(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

// snmpSlogAdapter bridges gosnmp's logger interface to slog.
type snmpSlogAdapter struct {
	logger interface {
		Debug(msg string, args ...any)
	}
}

func (a *snmpSlogAdapter) Print(v ...interface{}) {
	a.logger.Debug(fmt.Sprint(v...))
}

func (a *snmpSlogAdapter) Printf(format string, v ...interface{}) {
	a.logger.Debug(fmt.Sprintf(format, v...))
}
