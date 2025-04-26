package cursor

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
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
				return
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
			scanner.Scan()
			_ = scanner.Bytes()
			continue
		}

		if event[7:] == "message" {
			// Process the message content
			if scanner.Scan() {
				messageData := scanner.Bytes()
				for {
					if strings.Contains(string(messageData), "event: message") {
						scanner.Scan()
						messageData = scanner.Bytes()
					} else {
						break
					}
				}

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
		return aggregatedContent
	} else if sse {
		// Ensure we send [DONE] at the end if we haven't already
		ctx.Writer.WriteString("data: [DONE]\n\n")
		ctx.Writer.Flush()
		return aggregatedContent
	}
	return aggregatedContent
}

func newScanner(body io.ReadCloser) (scanner *bufio.Scanner) {
	// 每个字节占8位
	// 00000000 (0): 消息体(proto, 不需要解压)
	// 00000001 (1): 系统提示词(proto, 需要gzip解压)
	// 00000010 (2): 错误信息(JSON, 不需要解压)
	// 00000011 (3): 错误信息(JSON, 需要gzip解压)
	// 00000000 00000000 00000010 11011000 4个字节描述包体大小
	scanner = bufio.NewScanner(body)
	var (
		buffer   []byte
		position int
	)

	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		// 累积数据
		if len(buffer) == 0 {
			buffer = data
		} else if len(data) > 0 {
			buffer = append(buffer, data...)
		}

		// 如果数据不足，无法处理
		if len(buffer) < 5 {
			if atEOF {
				return len(data), nil, nil
			}
			return 0, nil, nil
		}

		// 读取消息头
		magic := buffer[position]
		dataLength := bytesToInt32(buffer[position+1 : position+5])

		// 检查我们是否有完整的数据块
		if len(buffer)-position < 5+dataLength {
			if atEOF {
				return len(data), nil, nil
			}
			return 0, nil, nil
		}

		// 提取数据块
		chunk := buffer[position+5 : position+5+dataLength]
		nextPosition := position + 5 + dataLength

		// 准备返回值
		var eventType string
		var resultChunk []byte

		// 根据magic处理不同类型的消息
		switch magic {
		case 0: // 消息体/proto, 不需要解压
			eventType = "event: message"
			var message ResMessage
			err = proto.Unmarshal(chunk, &message)
			if err != nil {
				position = nextPosition
				buffer = buffer[nextPosition:]
				return len(data), nil, err
			}
			if message.Msg != nil {
				resultChunk = []byte(message.Msg.Value)
			} else {
				resultChunk = []byte("")
			}

		case 1: // 系统提示词/proto, 需要gzip解压
			eventType = "event: system"
			reader, gzErr := emit.DecodeGZip(io.NopCloser(bytes.NewReader(chunk)))
			if gzErr != nil {
				position = nextPosition
				buffer = buffer[nextPosition:]
				return len(data), nil, gzErr
			}
			decompressed, readErr := io.ReadAll(reader)
			if readErr != nil {
				position = nextPosition
				buffer = buffer[nextPosition:]
				return len(data), nil, readErr
			}
			var message ResMessage
			err = proto.Unmarshal(decompressed, &message)
			if err != nil {
				position = nextPosition
				buffer = buffer[nextPosition:]
				return len(data), nil, err
			}
			if message.Msg != nil {
				resultChunk = []byte(message.Msg.Value)
			} else {
				resultChunk = []byte("")
			}

		case 2: // 错误信息/JSON, 不需要解压
			eventType = "event: error"
			resultChunk = chunk

		case 3: // 错误信息/JSON, 需要gzip解压
			eventType = "event: error"
			reader, gzErr := emit.DecodeGZip(io.NopCloser(bytes.NewReader(chunk)))
			if gzErr != nil {
				position = nextPosition
				buffer = buffer[nextPosition:]
				return len(data), nil, gzErr
			}
			decompressed, readErr := io.ReadAll(reader)
			if readErr != nil {
				position = nextPosition
				buffer = buffer[nextPosition:]
				return len(data), nil, readErr
			}
			resultChunk = decompressed

		default:
			// 未知的魔术数字，跳过
			position = nextPosition
			buffer = buffer[nextPosition:]
			return len(data), nil, nil
		}

		// 进入下一个块
		position = 0
		buffer = buffer[nextPosition:]

		if eventType != "" {
			if len(data) <= nextPosition {
				return len(data), []byte(eventType), nil
			} else {
				return nextPosition, []byte(eventType), nil
			}
		}

		return len(data), resultChunk, nil
	})

	return
}
