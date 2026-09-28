package qqbot

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Tencent/WeKnora/internal/im"
	"github.com/Tencent/WeKnora/internal/logger"
	secutils "github.com/Tencent/WeKnora/internal/utils"
	ws "github.com/gorilla/websocket"
)

type MessageHandler func(ctx context.Context, msg *im.IncomingMessage) error

// minKeepaliveTimeout floors the watchdog deadline. QQ's hello announces the
// heartbeat interval the gateway expects; the watchdog tolerates two missed
// cycles (like the WeCom client) but never less than this floor. A package
// var so tests can shrink it instead of sleeping for 90 seconds.
var minKeepaliveTimeout = 90 * time.Second

type LongConnClient struct {
	client  *Client
	handler MessageHandler

	mu     sync.Mutex
	conn   *ws.Conn
	seq    *int64
	closed bool

	// keepalive is the current watchdog deadline: how long the connection may
	// go without ANY inbound frame before the read deadline fires, ReadMessage
	// fails, and the reconnect loop takes over. Started at the floor, tightened
	// to 2× the hello-announced heartbeat interval after identify.
	keepalive atomic.Int64
}

func NewLongConnClient(client *Client, handler MessageHandler) *LongConnClient {
	c := &LongConnClient{client: client, handler: handler}
	c.keepalive.Store(int64(minKeepaliveTimeout))
	return c
}

// keepaliveFor turns the hello-announced heartbeat interval into the watchdog
// deadline: two missed cycles, floored at minKeepaliveTimeout.
func keepaliveFor(heartbeatInterval time.Duration) time.Duration {
	deadline := 2 * heartbeatInterval
	if deadline < minKeepaliveTimeout {
		return minKeepaliveTimeout
	}
	return deadline
}

func (c *LongConnClient) Start(ctx context.Context) error {
	logger.Infof(ctx, "[IM] QQBot WebSocket connecting...")
	attempt := 0
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := c.connectAndRun(ctx); err != nil {
			if ctx.Err() != nil || c.isClosed() {
				return ctx.Err()
			}
			attempt++
			delay := reconnectDelay(attempt)
			logger.Warnf(ctx, "[QQBot] connection lost: %v, reconnecting in %v", err, delay)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			continue
		}
		attempt = 0
	}
}

func (c *LongConnClient) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

func (c *LongConnClient) connectAndRun(ctx context.Context) error {
	gatewayURL, err := c.client.GatewayURL(ctx)
	if err != nil {
		return err
	}
	dialer := *ws.DefaultDialer
	dialer.NetDialContext = secutils.SSRFSafeDialContext
	conn, _, err := dialer.DialContext(ctx, gatewayURL, nil)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		if c.conn == conn {
			c.conn = nil
		}
		c.mu.Unlock()
		_ = conn.Close()
	}()

	// Watchdog: arm the read deadline before the first read. Any inbound
	// frame (dispatch, heartbeat ACK, control frame) re-arms it; if the
	// gateway goes silent — dead TCP, half-open socket, a kick without a
	// close frame — the deadline fires, ReadMessage fails, and the Start
	// loop reconnects. Mirrors the WeCom client's read-timeout model.
	c.keepalive.Store(int64(minKeepaliveTimeout))
	_ = conn.SetReadDeadline(time.Now().Add(minKeepaliveTimeout))
	conn.SetPingHandler(func(appData string) error {
		_ = conn.SetReadDeadline(time.Now().Add(time.Duration(c.keepalive.Load())))
		return conn.WriteControl(ws.PongMessage, []byte(appData), time.Now().Add(5*time.Second))
	})

	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Duration(c.keepalive.Load())))
		_, data, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		var payload gatewayPayload
		if err := json.Unmarshal(data, &payload); err != nil {
			logger.Warnf(ctx, "[QQBot] invalid payload: %v", err)
			continue
		}
		if payload.S != nil {
			c.seq = payload.S
		}
		switch payload.Op {
		case opHello:
			if err := c.handleHello(ctx, conn, payload.D); err != nil {
				return err
			}
		case opDispatch:
			msg, err := parseGatewayPayload(&payload)
			if err != nil {
				logger.Warnf(ctx, "[QQBot] parse event failed: %v", err)
				continue
			}
			if msg != nil {
				if err := c.handler(ctx, msg); err != nil {
					logger.Errorf(ctx, "[QQBot] handle message failed: %v", err)
				}
			}
		case opReconnect, opInvalidSession:
			return fmt.Errorf("gateway requested reconnect op=%d", payload.Op)
		case opHeartbeatACK:
		}
	}
}

func (c *LongConnClient) handleHello(ctx context.Context, conn *ws.Conn, raw json.RawMessage) error {
	var hello helloData
	if err := json.Unmarshal(raw, &hello); err != nil {
		return err
	}
	if hello.HeartbeatInterval <= 0 {
		hello.HeartbeatInterval = 45000
	}
	token, err := c.client.AccessToken(ctx)
	if err != nil {
		return err
	}
	identify := identifyData{
		Token:   "QQBot " + token,
		Intents: intentGroupAndC2C,
		Shard:   []int{0, 1},
	}
	payloadBytes, err := json.Marshal(identify)
	if err != nil {
		return err
	}
	if err := conn.WriteJSON(gatewayPayload{Op: opIdentify, D: payloadBytes}); err != nil {
		return err
	}
	// The gateway told us its heartbeat cadence; tighten the watchdog from
	// the floor to two missed cycles so a kicked connection is noticed fast.
	keepalive := keepaliveFor(time.Duration(hello.HeartbeatInterval) * time.Millisecond)
	c.keepalive.Store(int64(keepalive))
	go c.heartbeatLoop(ctx, conn, time.Duration(hello.HeartbeatInterval)*time.Millisecond)
	return nil
}

func (c *LongConnClient) heartbeatLoop(ctx context.Context, conn *ws.Conn, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			heartbeat, err := c.heartbeatPayload()
			if err == nil {
				err = conn.WriteJSON(heartbeat)
			}
			if err != nil {
				// A failed heartbeat write means the connection is dead from
				// our side; close it so the read loop unblocks immediately
				// instead of waiting out the watchdog deadline.
				_ = conn.Close()
				return
			}
		}
	}
}

func (c *LongConnClient) heartbeatPayload() (gatewayPayload, error) {
	c.mu.Lock()
	seq := c.seq
	c.mu.Unlock()
	data, err := json.Marshal(seq)
	if err != nil {
		return gatewayPayload{}, err
	}
	return gatewayPayload{Op: opHeartbeat, D: data}, nil
}

func (c *LongConnClient) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func reconnectDelay(attempt int) time.Duration {
	if attempt <= 1 {
		return time.Second
	}
	delay := time.Duration(attempt) * time.Second
	// The <= 0 guard mirrors the WeCom client: an overflowed (negative)
	// duration would bypass the max-delay cap and cause a busy reconnect loop.
	if delay > 30*time.Second || delay <= 0 {
		return 30 * time.Second
	}
	return delay
}
