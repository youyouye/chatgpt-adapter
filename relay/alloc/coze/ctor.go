package coze

import (
	"github.com/iocgo/sdk/proxy"

	_ "chatgpt-adapter/core/gin/inter"
	_ "chatgpt-adapter/core/gin/model"
	_ "github.com/gin-gonic/gin"
	_ "reflect"
)

// @Proxy(
//
//	target = "chatgpt-adapter/core/gin/inter.Adapter",
//	scan = "chatgpt-adapter/relay/llm/coze.api",
//	igm   = "!(Completion|ToolChoice)"
//
// )
func Proxy(ctx *proxy.Context) { InvocationHandler(ctx) }
