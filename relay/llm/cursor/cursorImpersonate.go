package cursor

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"github.com/imroc/req/v3"
	utls "github.com/refraction-networking/utls"
	"math/big"
	"strconv"
	"strings"

	"github.com/imroc/req/v3/http2"
)

// Identical for both Blink-based browsers (Chrome, Chromium, etc.) and WebKit-based browsers (Safari, etc.)
// Blink implementation: https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/platform/network/form_data_encoder.cc;drc=1d694679493c7b2f7b9df00e967b4f8699321093;l=130
// WebKit implementation: https://github.com/WebKit/WebKit/blob/47eea119fe9462721e5cc75527a4280c6d5f5214/Source/WebCore/platform/network/FormDataBuilder.cpp#L120
func webkitMultipartBoundaryFunc() string {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB"

	sb := strings.Builder{}
	sb.WriteString("----WebKitFormBoundary")

	for i := 0; i < 16; i++ {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters)-1)))
		if err != nil {
			panic(err)
		}

		sb.WriteByte(letters[index.Int64()])
	}

	return sb.String()
}

// Firefox implementation: https://searchfox.org/mozilla-central/source/dom/html/HTMLFormSubmission.cpp#355
func firefoxMultipartBoundaryFunc() string {
	sb := strings.Builder{}
	sb.WriteString("-------------------------")

	for i := 0; i < 3; i++ {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		u32 := binary.LittleEndian.Uint32(b[:])
		s := strconv.FormatUint(uint64(u32), 10)

		sb.WriteString(s)
	}

	return sb.String()
}

var (
	chromeHttp2Settings = []http2.Setting{
		{
			ID:  http2.SettingHeaderTableSize,
			Val: 65536,
		},
		{
			ID:  http2.SettingEnablePush,
			Val: 0,
		},
		{
			ID:  http2.SettingMaxConcurrentStreams,
			Val: 1000,
		},
		{
			ID:  http2.SettingInitialWindowSize,
			Val: 6291456,
		},
		{
			ID:  http2.SettingMaxHeaderListSize,
			Val: 262144,
		},
	}

	chromePseudoHeaderOrder = []string{
		":method",
		":authority",
		":scheme",
		":path",
	}

	chromeHeaderOrder = []string{
		"host",
		"pragma",
		"cache-control",
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"upgrade-insecure-requests",
		"user-agent",
		"accept",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-user",
		"sec-fetch-dest",
		"referer",
		"accept-encoding",
		"accept-language",
		"cookie",
	}

	chromeHeaders = map[string]string{
		//"pragma":                    "no-cache",
		//"cache-control":             "no-cache",
		//"sec-ch-ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
		//"sec-ch-ua-mobile":          "?0",
		//"sec-ch-ua-platform":        `"macOS"`,
		//"upgrade-insecure-requests": "1",
		"user-agent": "connect-es/1.6.1",
		//"accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		//"sec-fetch-site":            "none",
		//"sec-fetch-mode":            "navigate",
		//"sec-fetch-user":            "?1",
		//"sec-fetch-dest":            "document",
		//"accept-language":           "zh-CN,zh;q=0.9",
	}

	chromeHeaderPriority = http2.PriorityParam{
		StreamDep: 0,
		Exclusive: true,
		Weight:    255,
	}
)

func buildExtensionsFromJA3(extStr, curvesStr, pointFmtStr string) []utls.TLSExtension {
	var exts []utls.TLSExtension

	// 解析曲线
	var curves []utls.CurveID
	if curvesStr != "" {
		for _, c := range strings.Split(curvesStr, "-") {
			id, _ := strconv.Atoi(c)
			curves = append(curves, utls.CurveID(id))
		}
	}

	// 解析点格式
	var pointFormats []byte
	if pointFmtStr != "" {
		for _, p := range strings.Split(pointFmtStr, "-") {
			id, _ := strconv.Atoi(p)
			pointFormats = append(pointFormats, byte(id))
		}
	}

	// 解析扩展
	if extStr != "" {
		for _, e := range strings.Split(extStr, "-") {
			id, _ := strconv.Atoi(e)

			switch uint16(id) {
			case 0: // SNI
				exts = append(exts, &utls.SNIExtension{})
			case 5: // StatusRequest
				exts = append(exts, &utls.StatusRequestExtension{})
			case 10: // SupportedCurves
				exts = append(exts, &utls.SupportedCurvesExtension{Curves: curves})
			case 11: // SupportedPoints
				exts = append(exts, &utls.SupportedPointsExtension{SupportedPoints: pointFormats})
			case 13: // SignatureAlgorithms
				exts = append(exts, &utls.SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []utls.SignatureScheme{
						utls.ECDSAWithP256AndSHA256,
						utls.PSSWithSHA256,
						utls.PKCS1WithSHA256,
						utls.ECDSAWithP384AndSHA384,
						utls.PSSWithSHA384,
						utls.PKCS1WithSHA384,
						utls.PSSWithSHA512,
						utls.PKCS1WithSHA512,
					},
				})
			case 16: // ALPN
				exts = append(exts, &utls.ALPNExtension{
					AlpnProtocols: []string{"h2", "http/1.1"},
				})
			case 18: // SCT
				exts = append(exts, &utls.SCTExtension{})
			case 21: // PaddingExtension
				exts = append(exts, &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle})
			case 23: // ExtendedMasterSecret
				exts = append(exts, &utls.UtlsExtendedMasterSecretExtension{})
			case 35: // SessionTicket
				exts = append(exts, &utls.SessionTicketExtension{})
			case 43: // SupportedVersions
				exts = append(exts, &utls.SupportedVersionsExtension{
					Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12},
				})
			case 45: // PSKKeyExchangeModes
				exts = append(exts, &utls.PSKKeyExchangeModesExtension{
					Modes: []uint8{utls.PskModeDHE},
				})
			case 51: // KeyShare
				exts = append(exts, &utls.KeyShareExtension{
					KeyShares: []utls.KeyShare{
						{Group: utls.X25519},
						{Group: utls.CurveP256},
					},
				})
			case 65281: // RenegotiationInfo
				exts = append(exts, &utls.RenegotiationInfoExtension{
					Renegotiation: utls.RenegotiateOnceAsClient,
				})
			default:
				// 对于未知或不支持的扩展，添加空扩展
				exts = append(exts, &utls.GenericExtension{Id: uint16(id)})
			}
		}
	}

	return exts
}

// 定义uTLSConn包装utls.UConn
type uTLSConn struct {
	*utls.UConn
}

func (c *uTLSConn) ConnectionState() tls.ConnectionState {
	cs := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:                     cs.Version,
		HandshakeComplete:           cs.HandshakeComplete,
		DidResume:                   cs.DidResume,
		CipherSuite:                 cs.CipherSuite,
		NegotiatedProtocol:          cs.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  cs.NegotiatedProtocolIsMutual,
		ServerName:                  cs.ServerName,
		PeerCertificates:            cs.PeerCertificates,
		VerifiedChains:              cs.VerifiedChains,
		SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
		OCSPResponse:                cs.OCSPResponse,
		TLSUnique:                   cs.TLSUnique,
	}
}

// ImpersonateCursor impersonates Chrome browser (version 120).
func ImpersonateCursor(c *req.Client) {

	//// 解析JA3指纹
	//ja3 := "771,4865-4866-4867-49199-49195-49200-49196-49191-52393-52392-49161-49171-49162-49172-156-157-47-53,0-23-65281-10-11-35-13-51-45-43-21-41,29-23-24,0"
	//parts := strings.Split(ja3, ",")
	//
	//// 解析密码套件
	//cipherSuites := []uint16{}
	//if parts[1] != "" {
	//	for _, c := range strings.Split(parts[1], "-") {
	//		id, _ := strconv.Atoi(c)
	//		cipherSuites = append(cipherSuites, uint16(id))
	//	}
	//}
	//
	//// 创建自定义指纹处理函数
	//tlsHandshakeFn := func(ctx context.Context, addr string, plainConn net.Conn) (conn net.Conn, tlsState *tls.ConnectionState, err error) {
	//	colonPos := strings.LastIndex(addr, ":")
	//	if colonPos == -1 {
	//		colonPos = len(addr)
	//	}
	//	hostname := addr[:colonPos]
	//	tlsConfig := c.GetTLSClientConfig()
	//	utlsConfig := &utls.Config{
	//		ServerName:         hostname,
	//		InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
	//		// 其他配置项
	//	}
	//
	//	uconn := utls.UClient(plainConn, utlsConfig, utls.HelloCustom)
	//
	//	// 设置Hello参数
	//	spec := &utls.ClientHelloSpec{
	//		TLSVersMin:         tls.VersionTLS10, // 0x0301
	//		TLSVersMax:         tls.VersionTLS13, // 0x0303
	//		CipherSuites:       cipherSuites,
	//		CompressionMethods: []byte{0},
	//		Extensions:         buildExtensionsFromJA3(parts[2], parts[3], parts[4]),
	//	}
	//
	//	if err = uconn.ApplyPreset(spec); err != nil {
	//		return nil, nil, err
	//	}
	//
	//	uTLSConn := &uTLSConn{uconn}
	//	err = uTLSConn.HandshakeContext(ctx)
	//	if err != nil {
	//		return nil, nil, err
	//	}
	//
	//	cs := uconn.ConnectionState()
	//	conn = uTLSConn
	//	tlsState = &tls.ConnectionState{
	//		Version:                     cs.Version,
	//		HandshakeComplete:           cs.HandshakeComplete,
	//		DidResume:                   cs.DidResume,
	//		CipherSuite:                 cs.CipherSuite,
	//		NegotiatedProtocol:          cs.NegotiatedProtocol,
	//		NegotiatedProtocolIsMutual:  cs.NegotiatedProtocolIsMutual,
	//		ServerName:                  cs.ServerName,
	//		PeerCertificates:            cs.PeerCertificates,
	//		VerifiedChains:              cs.VerifiedChains,
	//		SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
	//		OCSPResponse:                cs.OCSPResponse,
	//		TLSUnique:                   cs.TLSUnique,
	//	}
	//	return
	//}
	//
	//c.Transport.SetTLSHandshake(tlsHandshakeFn)

	c.
		SetTLSFingerprint(utls.HelloRandomizedNoALPN).
		SetHTTP2SettingsFrame(chromeHttp2Settings...).
		SetHTTP2ConnectionFlow(15663105).
		SetCommonHeaders(chromeHeaders)
}

var (
	firefoxHttp2Settings = []http2.Setting{
		{
			ID:  http2.SettingHeaderTableSize,
			Val: 65536,
		},
		{
			ID:  http2.SettingInitialWindowSize,
			Val: 131072,
		},
		{
			ID:  http2.SettingMaxFrameSize,
			Val: 16384,
		},
	}

	firefoxPriorityFrames = []http2.PriorityFrame{
		{
			StreamID: 3,
			PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			},
		},
		{
			StreamID: 5,
			PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			},
		},
		{
			StreamID: 7,
			PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			},
		},
		{
			StreamID: 9,
			PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			},
		},
		{
			StreamID: 11,
			PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			},
		},
		{
			StreamID: 13,
			PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			},
		},
	}

	firefoxPseudoHeaderOrder = []string{
		":method",
		":path",
		":authority",
		":scheme",
	}

	firefoxHeaderOrder = []string{
		"user-agent",
		"accept",
		"accept-language",
		"accept-encoding",
		"referer",
		"cookie",
		"upgrade-insecure-requests",
		"sec-fetch-dest",
		"sec-fetch-mode",
		"sec-fetch-site",
		"sec-fetch-user",
		"te",
	}

	firefoxHeaders = map[string]string{
		"user-agent":                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
		"accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"accept-language":           "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
		"upgrade-insecure-requests": "1",
		"sec-fetch-dest":            "document",
		"sec-fetch-mode":            "navigate",
		"sec-fetch-site":            "same-origin",
		"sec-fetch-user":            "?1",
		//"te":                        "trailers",
	}

	firefoxHeaderPriority = http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	}
)

var (
	safariHttp2Settings = []http2.Setting{
		{
			ID:  http2.SettingInitialWindowSize,
			Val: 4194304,
		},
		{
			ID:  http2.SettingMaxConcurrentStreams,
			Val: 100,
		},
	}

	safariPseudoHeaderOrder = []string{
		":method",
		":scheme",
		":path",
		":authority",
	}

	safariHeaderOrder = []string{
		"accept",
		"sec-fetch-site",
		"cookie",
		"sec-fetch-dest",
		"accept-language",
		"sec-fetch-mode",
		"user-agent",
		"referer",
		"accept-encoding",
	}

	safariHeaders = map[string]string{
		"accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"sec-fetch-site":  "same-origin",
		"sec-fetch-dest":  "document",
		"accept-language": "zh-CN,zh-Hans;q=0.9",
		"sec-fetch-mode":  "navigate",
		"user-agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
	}

	safariHeaderPriority = http2.PriorityParam{
		StreamDep: 0,
		Exclusive: false,
		Weight:    254,
	}
)
