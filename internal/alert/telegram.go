package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// TelegramPayload is the JSON payload posted to Telegram's sendMessage endpoint.
type TelegramPayload struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode,omitempty"`
}

// BuildTelegramPayload builds the Telegram sendMessage payload for ev.
func BuildTelegramPayload(chatID string, ev Event) TelegramPayload {
	text := summary(ev)
	if d := detail(ev); d != "" {
		text += "\n" + d
	}
	return TelegramPayload{
		ChatID:    chatID,
		Text:      text,
		ParseMode: "Markdown",
	}
}

// TelegramNotifier posts alerts to a Telegram bot sendMessage endpoint.
type TelegramNotifier struct {
	BotToken string
	ChatID   string
	BaseURL  string // test hook; empty defaults to https://api.telegram.org
	Client   *http.Client
}

// Name implements Notifier.
func (n *TelegramNotifier) Name() string { return "telegram" }

func (n *TelegramNotifier) client() *http.Client {
	if n.Client != nil {
		return n.Client
	}
	return http.DefaultClient
}

func (n *TelegramNotifier) endpoint() string {
	base := n.BaseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	return fmt.Sprintf("%s/bot%s/sendMessage", base, n.BotToken)
}

// Notify implements Notifier.
func (n *TelegramNotifier) Notify(ctx context.Context, ev Event) error {
	payload := BuildTelegramPayload(n.ChatID, ev)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("telegram: marshal payload: %w", err)
	}
	return postJSON(ctx, n.client(), n.endpoint(), body, "telegram")
}
