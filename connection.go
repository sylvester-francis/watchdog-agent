package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sylvester-francis/watchdog-proto/protocol"
)

// Connection timing constants.
const (
	readWait  = 90 * time.Second
	pingEvery = 30 * time.Second
)

// Connection errors.
var (
	ErrAuthFailed     = errors.New("authentication failed")
	ErrAuthTimeout    = errors.New("authentication timeout")
	ErrConnectionLost = errors.New("connection lost")
)

// Connection manages the WebSocket connection to the hub.
type Connection struct {
	url       string
	apiKey    string
	version   string
	conn      *websocket.Conn
	logger    *slog.Logger
	sendCh    chan *protocol.Message
	closeCh   chan struct{}
	closeOnce sync.Once
	agentID   string
	agentName string
}

// NewConnection creates a new connection to the hub.
func NewConnection(url, apiKey, version string, logger *slog.Logger) (*Connection, error) {
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, resp, err := dialer.Dial(url, nil)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	// Reset read deadline when the hub sends us a WebSocket ping.
	// Without this, the read deadline set in readMessage() expires because
	// ping control frames don't unblock ReadMessage().
	conn.SetPingHandler(func(appData string) error {
		if err := conn.SetReadDeadline(time.Now().Add(readWait)); err != nil {
			return err
		}
		return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(5*time.Second))
	})

	return &Connection{
		url:     url,
		apiKey:  apiKey,
		version: version,
		conn:    conn,
		logger:  logger,
		sendCh:  make(chan *protocol.Message, 256),
		closeCh: make(chan struct{}),
	}, nil
}

// Authenticate performs the authentication handshake.
func (c *Connection) Authenticate(ctx context.Context) error {
	// Send auth message
	authMsg := protocol.NewAuthMessage(c.apiKey, c.version)
	if err := c.writeMessage(authMsg); err != nil {
		return fmt.Errorf("failed to send auth: %w", err)
	}

	// Wait for auth response with timeout
	authCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Read response
	responseCh := make(chan *protocol.Message, 1)
	errCh := make(chan error, 1)

	go func() {
		msg, err := c.readMessage()
		if err != nil {
			errCh <- err
			return
		}
		responseCh <- msg
	}()

	select {
	case <-authCtx.Done():
		return ErrAuthTimeout
	case err := <-errCh:
		return fmt.Errorf("failed to read auth response: %w", err)
	case msg := <-responseCh:
		return c.handleAuthResponse(msg)
	}
}

func (c *Connection) handleAuthResponse(msg *protocol.Message) error {
	switch msg.Type {
	case protocol.MsgTypeAuthAck:
		var payload protocol.AuthAckPayload
		if err := msg.ParsePayload(&payload); err != nil {
			return fmt.Errorf("failed to parse auth ack: %w", err)
		}
		c.agentID = payload.AgentID
		c.agentName = payload.AgentName
		c.logger.Info("authenticated",
			slog.String("agent_id", c.agentID),
			slog.String("agent_name", c.agentName),
		)
		return nil

	case protocol.MsgTypeAuthError:
		var payload protocol.AuthErrorPayload
		if err := msg.ParsePayload(&payload); err != nil {
			return ErrAuthFailed
		}
		return fmt.Errorf("%w: %s", ErrAuthFailed, payload.Error)

	default:
		return fmt.Errorf("unexpected message type: %s", msg.Type)
	}
}

// Run starts the message read loop.
func (c *Connection) Run(ctx context.Context, handler func(*protocol.Message)) error {
	// Start write pump
	go c.writePump(ctx)

	// Read loop
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.closeCh:
			return ErrConnectionLost
		default:
			msg, err := c.readMessage()
			if err != nil {
				return fmt.Errorf("read error: %w", err)
			}
			handler(msg)
		}
	}
}

func (c *Connection) writePump(ctx context.Context) {
	ticker := time.NewTicker(pingEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closeCh:
			return
		case msg := <-c.sendCh:
			if err := c.writeMessage(msg); err != nil {
				c.logger.Error("write error", slog.String("error", err.Error()))
				c.Close()
				return
			}
		case <-ticker.C:
			if err := c.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
				c.logger.Error("ping error", slog.String("error", err.Error()))
				c.Close()
				return
			}
		}
	}
}

// Send queues a message to be sent.
func (c *Connection) Send(msg *protocol.Message) error {
	select {
	case c.sendCh <- msg:
		return nil
	case <-c.closeCh:
		return ErrConnectionLost
	default:
		return errors.New("send buffer full")
	}
}

// SendHeartbeat sends a heartbeat message.
func (c *Connection) SendHeartbeat(monitorID, status string, latencyMs int, errorMsg string) error {
	msg := protocol.NewHeartbeatMessage(monitorID, status, latencyMs, errorMsg)
	return c.Send(msg)
}

// SendPong sends a pong message.
func (c *Connection) SendPong() error {
	return c.Send(protocol.NewPongMessage())
}

// Close closes the connection.
func (c *Connection) Close() {
	c.closeOnce.Do(func() {
		close(c.closeCh)
		c.conn.Close()
	})
}

// IsClosed returns true if the connection is closed.
func (c *Connection) IsClosed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

func (c *Connection) writeMessage(msg *protocol.Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	if err := c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	return c.conn.WriteMessage(websocket.TextMessage, data)
}

func (c *Connection) readMessage() (*protocol.Message, error) {
	if err := c.conn.SetReadDeadline(time.Now().Add(readWait)); err != nil {
		return nil, err
	}

	_, data, err := c.conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	var msg protocol.Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to parse message: %w", err)
	}

	return &msg, nil
}
