package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/sylvester-francis/watchdog-proto/protocol"
)

// Discovery constants.
const (
	discoveryTimeout     = 5 * time.Minute
	discoveryConcurrency = 50
	discoveryDialTimeout = 2 * time.Second
	discoveryMinPrefix   = 20 // /20 = 4096 hosts max
)

// discoveryMu ensures only one discovery scan runs at a time.
var discoveryMu sync.Mutex

// SNMP OIDs for device identification.
const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysObjectID = "1.3.6.1.2.1.1.2.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"
)

// Private IPv4 ranges (RFC 1918 + link-local).
var privateIPv4Ranges = []net.IPNet{
	{IP: net.IP{10, 0, 0, 0}, Mask: net.CIDRMask(8, 32)},
	{IP: net.IP{172, 16, 0, 0}, Mask: net.CIDRMask(12, 32)},
	{IP: net.IP{192, 168, 0, 0}, Mask: net.CIDRMask(16, 32)},
}

// handleDiscovery runs a network discovery scan. It validates the CIDR,
// performs a TCP ping sweep, probes live hosts via SNMP, and sends
// progress/result messages back to the hub.
func (a *Agent) handleDiscovery(payload *protocol.DiscoveryTaskPayload) {
	// Enforce single concurrent scan.
	if !discoveryMu.TryLock() {
		a.sendDiscoveryResult(payload.TaskID, "error", 0, nil, "another discovery scan is already running")
		return
	}
	defer discoveryMu.Unlock()

	// Hard timeout for the entire scan.
	ctx, cancel := context.WithTimeout(context.Background(), discoveryTimeout)
	defer cancel()

	// Validate and expand CIDR.
	hosts, err := expandCIDR(payload.Subnet)
	if err != nil {
		a.sendDiscoveryResult(payload.TaskID, "error", 0, nil, err.Error())
		return
	}

	a.logger.Info("discovery scan starting",
		slog.String("task_id", payload.TaskID),
		slog.String("subnet", payload.Subnet),
		slog.Int("host_count", len(hosts)),
	)

	// Send initial progress.
	a.sendDiscoveryResult(payload.TaskID, "running", 0, nil, "")

	// Phase 1: TCP ping sweep to find live hosts.
	liveHosts := a.discoverySweep(ctx, payload.TaskID, hosts)

	if ctx.Err() != nil {
		a.sendDiscoveryResult(payload.TaskID, "error", 0, nil, "discovery scan timed out")
		return
	}

	a.logger.Info("ping sweep complete",
		slog.String("task_id", payload.TaskID),
		slog.Int("live_hosts", len(liveHosts)),
	)

	// Phase 2: SNMP probe on live hosts.
	devices := a.discoveryProbe(ctx, payload, liveHosts)

	if ctx.Err() != nil {
		a.sendDiscoveryResult(payload.TaskID, "error", 50, nil, "discovery scan timed out during SNMP probe")
		return
	}

	// Send final result.
	a.sendDiscoveryResult(payload.TaskID, "complete", 100, devices, "")

	a.logger.Info("discovery scan complete",
		slog.String("task_id", payload.TaskID),
		slog.Int("devices_found", len(devices)),
	)
}

// discoverySweep performs a TCP ping sweep on ports 80 and 443 with
// progress updates every ~10% of hosts scanned.
func (a *Agent) discoverySweep(ctx context.Context, taskID string, hosts []net.IP) []net.IP {
	type sweepResult struct {
		ip   net.IP
		live bool
	}

	results := make([]sweepResult, len(hosts))
	sem := make(chan struct{}, discoveryConcurrency)
	var wg sync.WaitGroup

	// Progress tracking: report every ~10%.
	progressInterval := len(hosts) / 10
	if progressInterval < 1 {
		progressInterval = 1
	}
	var scannedCount int64
	var scannedMu sync.Mutex

	for i, host := range hosts {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		wg.Add(1)
		go func(idx int, ip net.IP) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			live := tcpProbe(ctx, ip, 80) || tcpProbe(ctx, ip, 443)
			results[idx] = sweepResult{ip: ip, live: live}

			// Update progress.
			scannedMu.Lock()
			scannedCount++
			count := scannedCount
			scannedMu.Unlock()

			if count%int64(progressInterval) == 0 {
				// Progress 0-50% for sweep phase.
				pct := int(float64(count) / float64(len(hosts)) * 50)
				if pct > 50 {
					pct = 50
				}
				a.sendDiscoveryResult(taskID, "running", pct, nil, "")
			}
		}(i, host)
	}
	wg.Wait()

	var liveHosts []net.IP
	for _, r := range results {
		if r.live {
			liveHosts = append(liveHosts, r.ip)
		}
	}
	return liveHosts
}

// tcpProbe attempts a TCP connection to ip:port with the discovery timeout.
func tcpProbe(ctx context.Context, ip net.IP, port int) bool {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	d := net.Dialer{Timeout: discoveryDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// discoveryProbe runs SNMP GET on live hosts to collect device identity.
func (a *Agent) discoveryProbe(ctx context.Context, payload *protocol.DiscoveryTaskPayload, liveHosts []net.IP) []protocol.DiscoveredDevice {
	if len(liveHosts) == 0 {
		return nil
	}

	devices := make([]protocol.DiscoveredDevice, len(liveHosts))
	sem := make(chan struct{}, discoveryConcurrency)
	var wg sync.WaitGroup

	// Progress tracking for SNMP phase (50-100%).
	progressInterval := len(liveHosts) / 10
	if progressInterval < 1 {
		progressInterval = 1
	}
	var probedCount int64
	var probedMu sync.Mutex

	snmpVersion := payload.SNMPVersion
	if snmpVersion == "" {
		snmpVersion = "2c"
	}

	snmpTimeout := time.Duration(payload.Timeout) * time.Second
	if snmpTimeout <= 0 || snmpTimeout > 30*time.Second {
		snmpTimeout = 5 * time.Second
	}

	for i, host := range liveHosts {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		wg.Add(1)
		go func(idx int, ip net.IP) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			dev := protocol.DiscoveredDevice{
				IP:            ip.String(),
				PingReachable: true,
			}

			// Reverse DNS lookup (best-effort).
			if names, err := net.LookupAddr(ip.String()); err == nil && len(names) > 0 {
				dev.Hostname = strings.TrimSuffix(names[0], ".")
			}

			// SNMP probe.
			sysDescr, sysOID, sysName, snmpOK := snmpProbeDevice(ctx, ip, payload.Community, snmpVersion, snmpTimeout)
			if snmpOK {
				dev.SNMPReachable = true
				dev.SysDescr = sysDescr
				dev.SysObjectID = sysOID
				dev.SysName = sysName
			}

			devices[idx] = dev

			// Update progress (50-100%).
			probedMu.Lock()
			probedCount++
			count := probedCount
			probedMu.Unlock()

			if count%int64(progressInterval) == 0 {
				pct := 50 + int(float64(count)/float64(len(liveHosts))*50)
				if pct > 99 {
					pct = 99
				}
				a.sendDiscoveryResult(payload.TaskID, "running", pct, nil, "")
			}
		}(i, host)
	}
	wg.Wait()

	// Filter out zero-value entries (from cancelled context).
	var result []protocol.DiscoveredDevice
	for _, d := range devices {
		if d.IP != "" {
			result = append(result, d)
		}
	}
	return result
}

// snmpProbeDevice performs SNMP GET for sysDescr, sysObjectID, sysName.
// Community string is never logged. Returns empty strings on failure.
func snmpProbeDevice(ctx context.Context, ip net.IP, community, version string, timeout time.Duration) (sysDescr, sysObjectID, sysName string, ok bool) {
	if community == "" {
		community = "public"
	}

	client := &gosnmp.GoSNMP{
		Target:  ip.String(),
		Port:    161,
		Timeout: timeout,
		Retries: 0,
	}

	switch version {
	case "2c", "":
		client.Version = gosnmp.Version2c
		client.Community = community
	case "1":
		client.Version = gosnmp.Version1
		client.Community = community
	default:
		// SNMPv3 not supported for discovery sweep — too many auth params.
		return "", "", "", false
	}

	if err := client.ConnectIPv4(); err != nil {
		return "", "", "", false
	}
	defer client.Conn.Close()

	// Single GET for all three OIDs.
	result, err := client.Get([]string{oidSysDescr, oidSysObjectID, oidSysName})
	if err != nil {
		return "", "", "", false
	}

	for _, pdu := range result.Variables {
		if pdu.Type == gosnmp.NoSuchObject || pdu.Type == gosnmp.NoSuchInstance {
			continue
		}
		name := strings.TrimPrefix(pdu.Name, ".")
		switch name {
		case oidSysDescr:
			sysDescr = formatSNMPValue(pdu)
		case oidSysObjectID:
			sysObjectID = fmt.Sprintf("%v", pdu.Value)
		case oidSysName:
			sysName = formatSNMPValue(pdu)
		}
	}

	return sysDescr, sysObjectID, sysName, true
}

// sendDiscoveryResult sends a discovery result message back to the hub.
func (a *Agent) sendDiscoveryResult(taskID, status string, progress int, devices []protocol.DiscoveredDevice, errMsg string) {
	msg := protocol.NewDiscoveryResultMessage(taskID, status, progress, devices, errMsg)
	if err := a.conn.Send(msg); err != nil {
		a.logger.Error("failed to send discovery result",
			slog.String("task_id", taskID),
			slog.String("error", err.Error()),
		)
	}
}

// expandCIDR validates a CIDR string and returns the list of host IPs.
// Rejects prefixes smaller than /20 (>4096 hosts) and non-private ranges.
func expandCIDR(cidr string) ([]net.IP, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %s", cidr)
	}

	// Determine prefix length.
	ones, bits := ipNet.Mask.Size()
	if bits == 0 {
		return nil, fmt.Errorf("invalid CIDR mask: %s", cidr)
	}

	// Enforce minimum prefix length.
	if ones < discoveryMinPrefix {
		return nil, fmt.Errorf("CIDR prefix /%d too large: minimum is /%d (max 4096 hosts)", ones, discoveryMinPrefix)
	}

	// Validate private range.
	if !isPrivateIP(ip) {
		return nil, fmt.Errorf("CIDR %s is not in a private range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)", cidr)
	}

	// IPv6 fc00::/7 support.
	if ip.To4() == nil {
		return expandIPv6CIDR(ipNet, ones, bits)
	}

	// Expand IPv4 hosts.
	hostCount := 1 << uint(bits-ones)
	if hostCount > 4096 {
		return nil, fmt.Errorf("too many hosts: %d (max 4096)", hostCount)
	}

	var hosts []net.IP
	ipInt := ipToUint32(ipNet.IP.To4())
	for i := 1; i < hostCount-1; i++ { // Skip network and broadcast addresses.
		hostIP := uint32ToIP(ipInt + uint32(i))
		hosts = append(hosts, hostIP)
	}

	return hosts, nil
}

// expandIPv6CIDR expands an IPv6 CIDR into host addresses.
func expandIPv6CIDR(ipNet *net.IPNet, ones, bits int) ([]net.IP, error) {
	hostBits := bits - ones
	if hostBits > 12 { // 2^12 = 4096
		return nil, fmt.Errorf("IPv6 CIDR too large: /%d yields more than 4096 hosts", ones)
	}

	hostCount := 1 << uint(hostBits)
	var hosts []net.IP
	baseIP := make(net.IP, len(ipNet.IP))
	copy(baseIP, ipNet.IP)

	for i := 1; i < hostCount-1; i++ {
		ip := make(net.IP, 16)
		copy(ip, baseIP)
		// Add offset to last bytes.
		offset := uint32(i)
		ip[15] += byte(offset & 0xFF)
		ip[14] += byte((offset >> 8) & 0xFF)
		if ipNet.Contains(ip) {
			hosts = append(hosts, ip)
		}
	}
	return hosts, nil
}

// isPrivateIP checks if an IP is in a private range.
func isPrivateIP(ip net.IP) bool {
	// IPv6 private range: fc00::/7
	if ip.To4() == nil {
		return ip[0]&0xfe == 0xfc // fc00::/7
	}

	ip4 := ip.To4()
	for _, r := range privateIPv4Ranges {
		if r.Contains(ip4) {
			return true
		}
	}
	return false
}

// ipToUint32 converts a 4-byte IPv4 address to a uint32.
func ipToUint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip)
}

// uint32ToIP converts a uint32 to an IPv4 address.
func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
