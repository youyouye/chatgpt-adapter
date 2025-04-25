package cursor

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/iocgo/sdk/env"

	"chatgpt-adapter/core/common"
	"chatgpt-adapter/core/logger"

	"github.com/bincooo/emit.io"
	"github.com/gin-gonic/gin"
	"github.com/golang/protobuf/proto"
)

const ginTokens = "__tokens__"

type chunkError struct {
	E struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Details []struct {
			Type  string `json:"type"`
			Debug struct {
				Error   string `json:"error"`
				Details struct {
					Title       string `json:"title"`
					Detail      string `json:"detail"`
					IsRetryable bool   `json:"isRetryable"`
				} `json:"details"`
				IsExpected bool `json:"isExpected"`
			} `json:"debug"`
			Value string `json:"value"`
		} `json:"details"`
	} `json:"error"`
}

func (ce chunkError) Error() string {
	message := ce.E.Message
	if len(ce.E.Details) > 0 {
		message = ce.E.Details[0].Debug.Details.Detail
	}
	return fmt.Sprintf("[%s] %s", ce.E.Code, message)
}

func waitMessage(r *http.Response, cancel func(str string) bool) (content string, err error) {
	defer r.Body.Close()
	scanner := newScanner(r.Body)
	for {
		if !scanner.Scan() {
			break
		}

		event := scanner.Text()
		if event == "" {
			continue
		}

		if !scanner.Scan() {
			break
		}

		chunk := scanner.Bytes()
		if len(chunk) == 0 {
			continue
		}

		if event[7:] == "error" {
			var chunkErr chunkError
			err = json.Unmarshal(chunk, &chunkErr)
			if err == nil {
				err = &chunkErr
			}
			return
		}

		if event[7:] == "system" || bytes.Equal(chunk, []byte("{}")) {
			continue
		}

		raw := string(chunk)
		logger.Debug("----- raw -----")
		logger.Debug(raw)
		if len(raw) > 0 {
			content += raw
			if cancel != nil && cancel(content) {
				return content, nil
			}
		}
	}

	return content, nil
}

func waitResponse(ctx *gin.Context, r *http.Response, sse bool) (content string) {
	defer r.Body.Close()
	logger.Info("waitResponse ...")
	completion := common.GetGinCompletion(ctx)
	thinkReason := env.Env.GetBool("server.think_reason")
	thinkReason = thinkReason && (slices.Contains([]string{"deepseek-r1", "claude-3.7-sonnet-thinking", "gemini-2.0-flash-thinking-exp"}, completion.Model[7:]))

	scanner := newScanner(r.Body)
	// Set response headers for streaming
	if sse {
		ctx.Writer.Header().Set("Content-Type", "text/event-stream")
		ctx.Writer.Header().Set("Cache-Control", "no-cache")
		ctx.Writer.Header().Set("Connection", "keep-alive")
		ctx.Writer.WriteHeader(http.StatusOK)
	}

	var aggregatedContent string // For non-streaming mode
	var finalID string

	for scanner.Scan() {
		event := scanner.Text()
		if event == "" {
			continue
		}

		chunk := scanner.Bytes()

		if len(chunk) == 0 {
			continue
		}

		if event[7:] == "error" {
			if bytes.Equal(chunk, []byte("{}")) {
				continue
			}
			var chunkErr chunkError
			err := json.Unmarshal(chunk, &chunkErr)
			if err == nil {
				err = &chunkErr
			}
			if sse {
				ctx.Writer.WriteString("data: [DONE]\n\n")
				ctx.Writer.Flush()
			} else {
				if len(aggregatedContent) <= 0 {
					ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				} else {
					break
				}
			}
		}

		if event[7:] == "system" || bytes.Equal(chunk, []byte("{}")) {
			continue
		}

		if event[7:] == "message" {
			// Process the message content
			if scanner.Scan() {
				messageData := scanner.Bytes()

				if sse {
					// Format as ChatGPT SSE
					id := uuid.NewString()
					if finalID == "" {
						finalID = id
					}
					if len(messageData) <= 0 {
						continue
					}

					sseMessage := map[string]interface{}{
						"id":      id,
						"object":  "chat.completion.chunk",
						"created": time.Now().Unix(),
						"model":   completion.Model[7:],
						"choices": []map[string]interface{}{
							{
								"index": 0,
								"delta": map[string]interface{}{
									"content": string(messageData),
								},
								"finish_reason": nil,
							},
						},
					}

					// Check if this is the end of the stream
					if len(messageData) == 0 || string(messageData) == "[DONE]" {
						sseMessage["choices"].([]map[string]interface{})[0]["finish_reason"] = "stop"
					}

					jsonData, err := json.Marshal(sseMessage)
					if err == nil {
						ctx.Writer.WriteString("data: " + string(jsonData) + "\n\n")
						ctx.Writer.Flush()
					}

					// If done, send final [DONE] message
					if len(messageData) == 0 || string(messageData) == "[DONE]" {
						ctx.Writer.WriteString("data: [DONE]\n\n")
						ctx.Writer.Flush()
						return
					}
				} else {
					// For non-streaming, accumulate content
					aggregatedContent += string(messageData)
				}
			}
		}
	}

	// Handle end of scanning
	if !sse && len(aggregatedContent) > 0 {
		// Return aggregated content in ChatGPT format
		response := map[string]interface{}{
			"id":      uuid.NewString(),
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   completion.Model[7:],
			"choices": []map[string]interface{}{
				{
					"index": 0,
					"message": map[string]interface{}{
						"role":    "assistant",
						"content": aggregatedContent,
					},
					"finish_reason": "stop",
				},
			},
		}
		ctx.JSON(http.StatusOK, response)
	} else if sse {
		// Ensure we send [DONE] at the end if we haven't already
		ctx.Writer.WriteString("data: [DONE]\n\n")
		ctx.Writer.Flush()
	}
	return
}

func newScanner(body io.ReadCloser) (scanner *bufio.Scanner) {
	// 每个字节占8位
	// 00000011 第一个字节是占位符，应该是用来代表消息类型的 假定 0: 消息体/proto, 1: 系统提示词/gzip, 2、3: 错误标记/gzip
	// 00000000 00000000 00000010 11011000 4个字节描述包体大小
	scanner = bufio.NewScanner(body)
	var (
		magic    byte
		chunkLen = -1
		setup    = 5
	)

	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return
		}

		if atEOF {
			return len(data), data, err
		}

		if chunkLen == -1 && len(data) < setup {
			return
		}

		if chunkLen == -1 {
			magic = data[0]
			chunkLen = bytesToInt32(data[1:setup])

			// 这部分应该是分割标记？或者补位
			if magic == 0 && chunkLen == 0 {
				chunkLen = -1
				return setup, []byte(""), err
			}

			if magic == 3 { // 假定它是错误标记
				return setup, []byte("event: error"), err
			}

			if magic == 2 { // 内部异常信息
				return setup, []byte("event: error"), err
			}

			if magic == 1 { // 系统提示词标记？
				return setup, []byte("event: system"), err
			}

			// magic == 0
			return setup, []byte("event: message"), err
		}

		if len(data) < chunkLen {
			return
		}

		chunk := data[:chunkLen]
		chunkLen = -1

		i := len(chunk)
		// 解码
		if emit.IsEncoding(chunk, "gzip") {
			reader, gzErr := emit.DecodeGZip(io.NopCloser(bytes.NewReader(chunk)))
			if gzErr != nil {
				err = gzErr
				return
			}
			chunk, err = io.ReadAll(reader)
		}
		if magic == 0 {
			// println(hex.EncodeToString(chunk))
			var message ResMessage
			err = proto.Unmarshal(chunk, &message)
			if err != nil {
				return
			}
			if message.Msg == nil {
				chunk = []byte("")
				return
			}
			chunk = []byte(message.Msg.Value)
		}
		return i, chunk, err
	})

	return
}
