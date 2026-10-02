package qqbot

import "encoding/json"

const (
	defaultAPIBaseURL = "https://api.sgroup.qq.com"
	appTokenURL       = "https://bots.qq.com/app/getAppAccessToken"
	defaultGatewayURL = "https://api.sgroup.qq.com/gateway"

	opDispatch        = 0
	opHeartbeat       = 1
	opIdentify        = 2
	opResume          = 6
	opReconnect       = 7
	opInvalidSession  = 9
	opHello           = 10
	opHeartbeatACK    = 11
	intentGroupAndC2C = 1 << 25

	eventC2CMessageCreate     = "C2C_MESSAGE_CREATE"
	eventGroupAtMessageCreate = "GROUP_AT_MESSAGE_CREATE"

	extraKeyMessageID = "message_id"
	extraKeyChatKind  = "chat_kind"
)

type gatewayPayload struct {
	ID string          `json:"id,omitempty"`
	Op int             `json:"op"`
	D  json.RawMessage `json:"d,omitempty"`
	S  *int64          `json:"s,omitempty"`
	T  string          `json:"t,omitempty"`
}

type helloData struct {
	HeartbeatInterval int `json:"heartbeat_interval"`
}

type identifyData struct {
	Token   string `json:"token"`
	Intents int    `json:"intents"`
	Shard   []int  `json:"shard,omitempty"`
}

// resumeData 用于断线重连时恢复会话（官方推荐：断开重连不需要重新 Identify，
// 发 OpCode 6 Resume 后网关会补发断线期间的事件，会话与事件流不中断）。
type resumeData struct {
	Token     string `json:"token"`
	SessionID string `json:"session_id"`
	Seq       int64  `json:"seq"`
}

// readyData 是鉴权成功后网关下发的 READY 事件负载，携带会话 id。
type readyData struct {
	SessionID string `json:"session_id"`
}

type tokenResponse struct {
	AccessToken string          `json:"access_token"`
	ExpiresIn   json.RawMessage `json:"expires_in"`
	Code        int             `json:"code"`
	Message     string          `json:"message"`
}

type gatewayResponse struct {
	URL string `json:"url"`
}

type messageEvent struct {
	ID          string         `json:"id"`
	Content     string         `json:"content"`
	GroupOpenID string         `json:"group_openid"`
	Author      qqbotAuthor    `json:"author"`
	Attachments []qqAttachment `json:"attachments"`
}

type qqbotAuthor struct {
	UserOpenID   string `json:"user_openid"`
	MemberOpenID string `json:"member_openid"`
	ID           string `json:"id"`
	Username     string `json:"username"`
	Bot          bool   `json:"bot"`
}

type qqAttachment struct {
	ContentType string `json:"content_type"`
	Filename    string `json:"filename"`
	Size        int64  `json:"size"`
	URL         string `json:"url"`
}

type sendMessageRequest struct {
	Content  string           `json:"content,omitempty"`
	MsgType  int              `json:"msg_type"`
	Markdown *markdownMessage `json:"markdown,omitempty"`
	MsgID    string           `json:"msg_id,omitempty"`
	MsgSeq   int              `json:"msg_seq,omitempty"`
}

type markdownMessage struct {
	Content string `json:"content,omitempty"`
}
