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

// reconnectBackoffResetAfter is how long a connection must stay up before the
// next reconnect restarts from the base delay. connectAndRun only ever returns
// on a lost connection, so without this the attempt counter would climb for the
// whole process lifetime and every later reconnect — even one after hours of a
// stable session — would sit at the 30s cap. A package var so tests can shrink
// it instead of holding a connection open for a minute.
var reconnectBackoffResetAfter = 60 * time.Second

type LongConnClient struct {
	client  *Client
	handler MessageHandler

	mu        sync.Mutex
	conn      *ws.Conn
	seq       *int64
	sessionID *string // READY 事件下发的会话 id；非空时断线重连走 op6 Resume
	closed    bool

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
		startedAt := time.Now()
		err := c.connectAndRun(ctx)
		if ctx.Err() != nil || c.isClosed() {
			return ctx.Err()
		}
		// The gateway rotates sessions roughly hourly (op=7), so a connection
		// that stayed up well past one rotation must not inherit the backoff
		// that earlier short-lived attempts accumulated.
		if time.Since(startedAt) >= reconnectBackoffResetAfter {
			attempt = 0
		}
		attempt++
		delay := reconnectDelay(attempt)
		logger.Warnf(ctx, "[QQBot] connection lost: %v, reconnecting in %v", err, delay)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
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
	// The heartbeat goroutine must live and die with THIS connection. Registered
	// after the cleanup defer above, so it runs first (defers are LIFO) and the
	// goroutine sees a cancelled context before the socket is closed — otherwise
	// every reconnect leaves the previous goroutine ticking until it trips over
	// the closed socket ("heartbeat write failed ... use of closed network
	// connection").
	connCtx, cancelConn := context.WithCancel(ctx)
	defer cancelConn()

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
			c.mu.Lock()
			c.seq = payload.S
			c.mu.Unlock()
		}
		switch payload.Op {
		case opHello:
			if err := c.handleHello(connCtx, conn, payload.D); err != nil {
				return err
			}
		case opDispatch:
			// READY 事件携带 session_id：保存后断线重连可走 op6 Resume
			// （官方推荐：断开重连不需要重新 Identify，Resume 会补发断线期间事件）
			if payload.T == "READY" {
				var rd readyData
				if err := json.Unmarshal(payload.D, &rd); err == nil && rd.SessionID != "" {
					c.mu.Lock()
					sid := rd.SessionID
					c.sessionID = &sid
					c.mu.Unlock()
					logger.Infof(ctx, "[QQBot] session established: %s", sid)
				}
			}
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
		case opReconnect:
			// 网关要求重连：保留 session，重连循环会走 op6 Resume 恢复会话
			return fmt.Errorf("gateway requested reconnect op=7")
		case opInvalidSession:
			// 会话失效（Resume 被拒等）：清掉会话，重连循环回退 op2 Identify
			c.mu.Lock()
			c.sessionID = nil
			c.seq = nil
			c.mu.Unlock()
			logger.Warnf(ctx, "[QQBot] invalid session (op=9), will re-identify on reconnect")
			return fmt.Errorf("gateway sent invalid session op=9")
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
	c.mu.Lock()
	sid := c.sessionID
	seq := c.seq
	c.mu.Unlock()
	if sid != nil && seq != nil {
		// 官方推荐（QQ 开放平台 ws 文档 + 官方 Node SDK 同款设计）：断开重连
		// 不需要重新 Identify，发 OpCode 6 Resume 恢复会话，网关会补发断线
		// 期间的事件，会话与事件流不中断。Resume 被拒时网关下发 op9
		// invalid session，connectAndRun 会清会话并走 Identify 回退。
		resume := resumeData{
			Token:     "QQBot " + token,
			SessionID: *sid,
			Seq:       *seq,
		}
		payloadBytes, err := json.Marshal(resume)
		if err != nil {
			return err
		}
		if err := conn.WriteJSON(gatewayPayload{Op: opResume, D: payloadBytes}); err != nil {
			return err
		}
		logger.Infof(ctx, "[QQBot] resuming session %s (seq=%d)", *sid, *seq)
	} else {
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
	counter := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			counter++
			// 观测日志：每 10 次心跳（约 7.5 分钟）打一条，用于定位"服务端 30+ 分钟
			// 主动 RST"时心跳是否一直存活——若日志显示心跳持续到 RST 前一刻，
			// 则排除客户端心跳缺失，指向服务端/链路侧清理
			if counter == 1 || counter%10 == 0 {
				logger.Infof(ctx, "[QQBot] heartbeat #%d sent (interval=%v)", counter, interval)
			}
			heartbeat, err := c.heartbeatPayload()
			if err == nil {
				err = conn.WriteJSON(heartbeat)
			}
			if err != nil {
				// A failed heartbeat write means the connection is dead from
				// our side; close it so the read loop unblocks immediately
				// instead of waiting out the watchdog deadline. When the context
				// is already cancelled this connection is being replaced, so the
				// failure is expected teardown noise, not a warning.
				if ctx.Err() == nil {
					logger.Warnf(ctx, "[QQBot] heartbeat write failed at #%d: %v", counter, err)
				}
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
