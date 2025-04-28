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
	reader := bufio.NewReader(r.Body)

	for {
		// 读取消息头
		header := make([]byte, 5)
		_, err = io.ReadFull(reader, header)
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return
		}

		// 解析消息头
		magic := header[0]
		dataLength := bytesToInt32(header[1:5])

		// 读取消息体
		chunk := make([]byte, dataLength)
		_, err = io.ReadFull(reader, chunk)
		if err != nil {
			return
		}

		// 处理消息
		var messageContent string

		switch magic {
		case 0: // 消息体/proto, 不需要解压
			var message ResMessage
			err = proto.Unmarshal(chunk, &message)
			if err != nil {
				return
			}
			if message.Msg != nil {
				messageContent = message.Msg.Value
			}

		case 1: // 系统提示词/proto, 需要gzip解压
			var gzReader io.ReadCloser
			gzReader, err = emit.DecodeGZip(io.NopCloser(bytes.NewReader(chunk)))
			if err != nil {
				return
			}
			var decompressed []byte
			decompressed, err = io.ReadAll(gzReader)
			if err != nil {
				return
			}
			var message ResMessage
			err = proto.Unmarshal(decompressed, &message)
			if err != nil {
				return
			}
			if message.Msg != nil {
				messageContent = message.Msg.Value
			}

		case 2: // 错误信息/JSON, 不需要解压
			var chunkErr chunkError
			err = json.Unmarshal(chunk, &chunkErr)
			if err == nil {
				err = &chunkErr
			}
			return

		case 3: // 错误信息/JSON, 需要gzip解压
			var gzReader io.ReadCloser
			gzReader, err = emit.DecodeGZip(io.NopCloser(bytes.NewReader(chunk)))
			if err != nil {
				return
			}
			var decompressed []byte
			decompressed, err = io.ReadAll(gzReader)
			if err != nil {
				return
			}
			var chunkErr chunkError
			err = json.Unmarshal(decompressed, &chunkErr)
			if err == nil {
				err = &chunkErr
			}
			return
		}

		// 处理返回内容
		if messageContent != "" {
			logger.Debug("----- raw -----")
			logger.Debug(messageContent)
			content += messageContent
			if cancel != nil && cancel(content) {
				return content, nil
			}
		}
	}
}

func waitResponse(ctx *gin.Context, r *http.Response, sse bool) (content string) {
	defer r.Body.Close()
	logger.Info("waitResponse ...")
	completion := common.GetGinCompletion(ctx)
	thinkReason := env.Env.GetBool("server.think_reason")
	thinkReason = thinkReason && (slices.Contains([]string{"deepseek-r1", "claude-3.7-sonnet-thinking", "gemini-2.0-flash-thinking-exp"}, completion.Model[7:]))

	reader := bufio.NewReader(r.Body)

	var aggregatedContent string // For non-streaming mode
	var finalID string

	isFirst := true

	for {
		// 读取消息头
		header := make([]byte, 5)
		n, err := io.ReadFull(reader, header)
		if err != nil {
			if err == io.EOF || n == 0 {
				break
			}
			logger.Error("读取消息头失败:", err)
			break
		}

		// 解析消息头
		magic := header[0]
		dataLength := bytesToInt32(header[1:5])

		// 读取消息体
		chunk := make([]byte, dataLength)
		_, err = io.ReadFull(reader, chunk)
		if err != nil {
			logger.Error("读取消息体失败:", err)
			break
		}

		// 处理不同类型的消息
		switch magic {
		case 0: // 消息体/proto, 不需要解压
			var message ResMessage
			err = proto.Unmarshal(chunk, &message)
			if err != nil {
				logger.Error("解析消息失败:", err)
				continue
			}

			if message.Msg == nil || message.Msg.Value == "" {
				continue
			}

			messageData := []byte(message.Msg.Value)

			if sse {
				// Format as ChatGPT SSE
				id := uuid.NewString()
				if finalID == "" {
					finalID = id
				}

				if isFirst {
					ctx.Writer.Header().Set("Content-Type", "text/event-stream")
					ctx.Writer.Header().Set("Cache-Control", "no-cache")
					ctx.Writer.Header().Set("Connection", "keep-alive")
					ctx.Writer.WriteHeader(http.StatusOK)
					isFirst = false
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
				if string(messageData) == "[DONE]" {
					sseMessage["choices"].([]map[string]interface{})[0]["finish_reason"] = "stop"
				}

				jsonData, err := json.Marshal(sseMessage)
				if err == nil {
					ctx.Writer.WriteString("data: " + string(jsonData) + "\n\n")
					ctx.Writer.Flush()
				}

				// If done, send final [DONE] message
				if string(messageData) == "[DONE]" {
					ctx.Writer.WriteString("data: [DONE]\n\n")
					ctx.Writer.Flush()
					return
				}
			} else {
				// For non-streaming, accumulate content
				aggregatedContent += string(messageData)
			}

		case 1: // 系统提示词/proto, 需要gzip解压
			// 系统消息一般不需要显示给用户，忽略
			continue

		case 2, 3: // 错误信息/JSON
			var errContent []byte
			if magic == 3 { // 需要解压
				gzReader, err := emit.DecodeGZip(io.NopCloser(bytes.NewReader(chunk)))
				if err != nil {
					logger.Error("解压错误消息失败:", err)
					continue
				}
				errContent, err = io.ReadAll(gzReader)
				if err != nil {
					logger.Error("读取解压内容失败:", err)
					continue
				}
			} else {
				errContent = chunk
			}

			if bytes.Equal(errContent, []byte("{}")) {
				continue
			}

			var chunkErr chunkError
			err = json.Unmarshal(errContent, &chunkErr)
			if err != nil {
				logger.Error("解析错误消息失败:", err)
				continue
			}

			if sse {
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": chunkErr.Error()})
				return
			} else {
				if len(aggregatedContent) <= 0 {
					ctx.JSON(http.StatusInternalServerError, gin.H{"error": chunkErr.Error()})
					return
				} else {
					break
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
