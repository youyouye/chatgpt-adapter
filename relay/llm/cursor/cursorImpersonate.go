package cursor

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"github.com/imroc/req/v3"
	utls "github.com/refraction-networking/utls"
	"math/big"
	"net"
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

func buildExtensionsFromJA3(extensionsStr, ellipticCurvesStr, ellipticCurvePointFormatsStr string) []utls.TLSExtension {
	var extensions []utls.TLSExtension

	// 解析扩展类型
	if extensionsStr != "" {
		for _, extStr := range strings.Split(extensionsStr, "-") {
			extID, _ := strconv.Atoi(extStr)

			// 根据扩展ID创建对应的扩展
			switch uint16(extID) {
			case 0: // SNI
				extensions = append(extensions, &utls.SNIExtension{})
			case 5: // StatusRequest
				extensions = append(extensions, &utls.StatusRequestExtension{})
			case 10: // SupportedCurves
				// 解析椭圆曲线
				var curves []utls.CurveID
				if ellipticCurvesStr != "" {
					for _, c := range strings.Split(ellipticCurvesStr, "-") {
						id, _ := strconv.Atoi(c)
						curves = append(curves, utls.CurveID(uint16(id)))
					}
				}
				extensions = append(extensions, &utls.SupportedCurvesExtension{Curves: curves})
			case 11: // ECPointFormats
				// 解析椭圆曲线点格式
				var formats []byte
				if ellipticCurvePointFormatsStr != "" {
					for _, f := range strings.Split(ellipticCurvePointFormatsStr, "-") {
						id, _ := strconv.Atoi(f)
						formats = append(formats, byte(id))
					}
				}
				extensions = append(extensions, &utls.SupportedPointsExtension{SupportedPoints: formats})
			case 13: // SignatureAlgorithms
				extensions = append(extensions, &utls.SignatureAlgorithmsExtension{
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
				extensions = append(extensions, &utls.ALPNExtension{
					AlpnProtocols: []string{"h2", "http/1.1"},
				})
			case 23: // ExtendedMasterSecret
				extensions = append(extensions, &utls.UtlsExtendedMasterSecretExtension{})
			case 35: // SessionTicket
				extensions = append(extensions, &utls.SessionTicketExtension{})
			case 43: // SupportedVersions
				extensions = append(extensions, &utls.SupportedVersionsExtension{
					Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10},
				})
			case 45: // PSKKeyExchangeModes
				extensions = append(extensions, &utls.PSKKeyExchangeModesExtension{
					Modes: []uint8{1}, // PSK with (EC)DHE key establishment
				})
			case 51: // KeyShare
				extensions = append(extensions, &utls.KeyShareExtension{
					KeyShares: []utls.KeyShare{
						{Group: utls.X25519},
						{Group: utls.CurveP256},
					},
				})
			case 65281: // RenegotiationInfo
				extensions = append(extensions, &utls.RenegotiationInfoExtension{
					Renegotiation: utls.RenegotiateOnceAsClient,
				})
			}
		}
	}

	return extensions
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

func parseJA4Fingerprint(ja4String string) (tlsVersion uint16, cipherSuites []uint16, extensions []utls.TLSExtension, alpn []string) {
	parts := strings.Split(ja4String, "_")

	// 解析TLS版本
	if len(parts) > 0 {
		switch parts[0] {
		case "t10":
			tlsVersion = tls.VersionTLS10
		case "t11":
			tlsVersion = tls.VersionTLS11
		case "t12":
			tlsVersion = tls.VersionTLS12
		case "t13":
			tlsVersion = tls.VersionTLS13
		default:
			tlsVersion = tls.VersionTLS13 // 默认
		}
	}

	// 解析密码套件
	if len(parts) > 1 && parts[1] != "" {
		suitesHex := strings.Split(parts[1], "")
		for i := 0; i < len(suitesHex); i += 4 {
			if i+4 <= len(suitesHex) {
				hexStr := strings.Join(suitesHex[i:i+4], "")
				if hexVal, err := strconv.ParseUint(hexStr, 16, 16); err == nil {
					cipherSuites = append(cipherSuites, uint16(hexVal))
				}
			}
		}
	}

	// 解析扩展
	if len(parts) > 2 && parts[2] != "" {
		extCodes := strings.Split(parts[2], "")
		for _, code := range extCodes {
			// 将JA4扩展代码映射到实际的TLS扩展
			ext := mapJA4ExtensionToTLS(code)
			if ext != nil {
				extensions = append(extensions, ext)
			}
		}
	}

	// 解析ALPN
	if len(parts) > 3 && parts[3] != "" {
		alpnCodes := strings.Split(parts[3], "")
		for _, code := range alpnCodes {
			protocol := mapJA4ALPNToProtocol(code)
			if protocol != "" {
				alpn = append(alpn, protocol)
			}
		}
	}

	return
}

// 将JA4扩展代码映射到实际的TLS扩展
func mapJA4ExtensionToTLS(extCode string) utls.TLSExtension {
	switch extCode {
	case "0": // SNI
		return &utls.SNIExtension{}
	case "1": // StatusRequest
		return &utls.StatusRequestExtension{}
	case "2": // SupportedCurves
		return &utls.SupportedCurvesExtension{
			Curves: []utls.CurveID{
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			},
		}
	case "3": // ECPointFormats
		return &utls.SupportedPointsExtension{SupportedPoints: []byte{0}}
	case "4": // SignatureAlgorithms
		return &utls.SignatureAlgorithmsExtension{
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
		}
	case "5": // ALPN
		return &utls.ALPNExtension{}
	case "6": // ExtendedMasterSecret
		return &utls.UtlsExtendedMasterSecretExtension{}
	case "7": // SessionTicket
		return &utls.SessionTicketExtension{}
	case "8": // SupportedVersions
		return &utls.SupportedVersionsExtension{
			Versions: []uint16{
				tls.VersionTLS13,
				tls.VersionTLS12,
				tls.VersionTLS11,
				tls.VersionTLS10,
			},
		}
	case "9": // PSKKeyExchangeModes
		return &utls.PSKKeyExchangeModesExtension{
			Modes: []uint8{1}, // PSK with (EC)DHE key establishment
		}
	case "A": // KeyShare
		return &utls.KeyShareExtension{
			KeyShares: []utls.KeyShare{
				{Group: utls.X25519},
				{Group: utls.CurveP256},
			},
		}
	case "B": // RenegotiationInfo
		return &utls.RenegotiationInfoExtension{
			Renegotiation: utls.RenegotiateOnceAsClient,
		}
	case "G": // GREASE
		return &utls.UtlsGREASEExtension{}
	// 可以继续添加更多的扩展映射
	default:
		return nil
	}
}

// 将JA4 ALPN代码映射到实际的协议
func mapJA4ALPNToProtocol(alpnCode string) string {
	switch alpnCode {
	case "h":
		return "h2"
	case "H":
		return "http/1.1"
	case "s":
		return "spdy/3.1"
	case "q":
		return "quic"
	case "Q":
		return "hq"
	// 添加更多的ALPN协议映射
	default:
		return ""
	}
}

// 使用JA4指纹创建TLS配置
func createTLSConfigFromJA4(ja4String string) (*utls.Config, *utls.ClientHelloSpec) {
	tlsVersion, cipherSuites, extensions, alpnProtocols := parseJA4Fingerprint(ja4String)

	// 如果解析出了ALPN协议，更新ALPN扩展
	for i, ext := range extensions {
		if alpnExt, ok := ext.(*utls.ALPNExtension); ok && len(alpnProtocols) > 0 {
			alpnExt.AlpnProtocols = alpnProtocols
			extensions[i] = alpnExt
			break
		}
	}

	// 如果没有找到ALPN扩展但有ALPN协议，添加一个ALPN扩展
	hasAlpnExt := false
	for _, ext := range extensions {
		if _, ok := ext.(*utls.ALPNExtension); ok {
			hasAlpnExt = true
			break
		}
	}

	if !hasAlpnExt && len(alpnProtocols) > 0 {
		extensions = append(extensions, &utls.ALPNExtension{
			AlpnProtocols: alpnProtocols,
		})
	}

	// 创建ClientHelloSpec
	spec := &utls.ClientHelloSpec{
		TLSVersMin:         tls.VersionTLS10,
		TLSVersMax:         tlsVersion,
		CipherSuites:       cipherSuites,
		CompressionMethods: []byte{0},
		Extensions:         extensions,
	}

	// 创建TLS配置
	config := &utls.Config{
		NextProtos:         alpnProtocols,
		InsecureSkipVerify: true, // 根据需要调整
	}

	return config, spec
}

func ImpersonateCursorRandom(c *req.Client) {
	c.
		SetTLSFingerprint(utls.HelloRandomizedNoALPN).
		SetHTTP2SettingsFrame(chromeHttp2Settings...).
		SetHTTP2ConnectionFlow(15663105).
		SetCommonHeaders(chromeHeaders)
}

func buildClientHelloSpecFromFingerprints(ja3String, ja4String, hostname string) *utls.ClientHelloSpec {
	// 解析JA3
	ja3Parts := strings.Split(ja3String, ",")

	// 解析TLS版本
	tlsVers := uint16(tls.VersionTLS12) // 默认值
	if len(ja3Parts) > 0 {
		if v, err := strconv.Atoi(ja3Parts[0]); err == nil {
			if v == 771 {
				tlsVers = tls.VersionTLS12
			} else if v == 772 {
				tlsVers = tls.VersionTLS13
			}
		}
	}

	// 解析JA3密码套件
	var cipherSuites []uint16
	if len(ja3Parts) > 1 && ja3Parts[1] != "" {
		for _, c := range strings.Split(ja3Parts[1], "-") {
			if id, err := strconv.Atoi(c); err == nil {
				cipherSuites = append(cipherSuites, uint16(id))
			}
		}
	}

	// 解析JA3扩展
	var ja3Extensions []string
	if len(ja3Parts) > 2 {
		ja3Extensions = strings.Split(ja3Parts[2], "-")
	}

	// 解析JA3椭圆曲线
	var curves []utls.CurveID
	if len(ja3Parts) > 3 && ja3Parts[3] != "" {
		for _, c := range strings.Split(ja3Parts[3], "-") {
			if id, err := strconv.Atoi(c); err == nil {
				curves = append(curves, utls.CurveID(uint16(id)))
			}
		}
	}

	// 解析JA3椭圆曲线点格式
	var pointFormats []byte
	if len(ja3Parts) > 4 && ja3Parts[4] != "" {
		for _, p := range strings.Split(ja3Parts[4], "-") {
			if id, err := strconv.Atoi(p); err == nil {
				pointFormats = append(pointFormats, byte(id))
			}
		}
	}

	// 解析JA4
	ja4Parts := strings.Split(ja4String, "_")

	// 从JA4解析TLS版本
	if len(ja4Parts) > 0 {
		if strings.HasPrefix(ja4Parts[0], "t13") {
			tlsVers = tls.VersionTLS13
		} else if strings.HasPrefix(ja4Parts[0], "t12") {
			tlsVers = tls.VersionTLS12
		}
	}

	// 从JA4解析ALPN协议
	var alpnProtocols []string
	if len(ja4Parts) > 0 {
		// 检查JA4字符串中是否包含h2标记
		if strings.Contains(ja4Parts[0], "h2") {
			alpnProtocols = append(alpnProtocols, "h2")
		}
		// 可能还有其他ALPN协议
		if strings.Contains(ja4Parts[0], "http/1.1") || strings.Contains(ja4Parts[0], "h1") {
			alpnProtocols = append(alpnProtocols, "http/1.1")
		}
	}

	// 构建扩展列表
	extensions := []utls.TLSExtension{
		&utls.SNIExtension{ServerName: hostname},
	}

	// 确保包含必要的扩展
	hasAlpn := false
	hasCurves := false
	hasPoints := false

	// 处理JA3指定的扩展
	for _, extStr := range ja3Extensions {
		extID, _ := strconv.Atoi(extStr)

		switch uint16(extID) {
		case 0: // SNI - 已添加
			continue
		case 5: // Status Request
			extensions = append(extensions, &utls.StatusRequestExtension{})
		case 10: // Supported Curves
			hasCurves = true
			extensions = append(extensions, &utls.SupportedCurvesExtension{Curves: curves})
		case 11: // EC Point Formats
			hasPoints = true
			extensions = append(extensions, &utls.SupportedPointsExtension{SupportedPoints: pointFormats})
		case 13: // Signature Algorithms
			extensions = append(extensions, &utls.SignatureAlgorithmsExtension{
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
			hasAlpn = true
			extensions = append(extensions, &utls.ALPNExtension{AlpnProtocols: alpnProtocols})
		case 21: // Padding
			extensions = append(extensions, &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle})
		case 23: // Extended Master Secret
			extensions = append(extensions, &utls.UtlsExtendedMasterSecretExtension{})
		case 35: // SessionTicket
			extensions = append(extensions, &utls.SessionTicketExtension{})
		case 43: // Supported Versions
			if tlsVers >= tls.VersionTLS13 {
				extensions = append(extensions, &utls.SupportedVersionsExtension{
					Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
				})
			}
		case 45: // PSK Key Exchange Modes
			if tlsVers >= tls.VersionTLS13 {
				extensions = append(extensions, &utls.PSKKeyExchangeModesExtension{
					Modes: []uint8{utls.PskModeDHE},
				})
			}
		case 51: // Key Share
			if tlsVers >= tls.VersionTLS13 {
				extensions = append(extensions, &utls.KeyShareExtension{
					KeyShares: []utls.KeyShare{
						{Group: utls.X25519},
						{Group: utls.CurveP256},
					},
				})
			}
		case 65281: // Renegotiation Info
			extensions = append(extensions, &utls.RenegotiationInfoExtension{
				Renegotiation: utls.RenegotiateOnceAsClient,
			})
		}
	}

	// 确保重要扩展被包含
	if !hasAlpn && len(alpnProtocols) > 0 {
		extensions = append(extensions, &utls.ALPNExtension{AlpnProtocols: alpnProtocols})
	}
	if !hasCurves && len(curves) > 0 {
		extensions = append(extensions, &utls.SupportedCurvesExtension{Curves: curves})
	}
	if !hasPoints && len(pointFormats) > 0 {
		extensions = append(extensions, &utls.SupportedPointsExtension{SupportedPoints: pointFormats})
	}

	// 创建ClientHelloSpec
	spec := &utls.ClientHelloSpec{
		TLSVersMin:         tls.VersionTLS10,
		TLSVersMax:         tlsVers,
		CipherSuites:       cipherSuites,
		CompressionMethods: []byte{0}, // no compression
		Extensions:         extensions,
	}

	return spec
}

// ImpersonateCursor impersonates Chrome browser (version 120).
func ImpersonateCursor(c *req.Client) {
	c.
		SetHTTP2SettingsFrame(chromeHttp2Settings...).
		SetHTTP2ConnectionFlow(15663105).
		SetCommonHeaders(chromeHeaders)

	// 定义JA3和JA4指纹
	ja3String := "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0"
	ja4String := "t13d2014h1_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,002b,002d,0033,ff01_0403,0804,0401,0503,0805,0805,0501,0806,0601,0201"

	tlsHandshakeFn := func(ctx context.Context, addr string, plainConn net.Conn) (conn net.Conn, tlsState *tls.ConnectionState, err error) {
		colonPos := strings.LastIndex(addr, ":")
		if colonPos == -1 {
			colonPos = len(addr)
		}
		hostname := addr[:colonPos]

		// 创建TLS配置
		config := &utls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: true,
		}

		// 使用预定义的浏览器配置作为基础
		uconn := utls.UClient(plainConn, config, utls.HelloCustom)

		// 手动构建一个能同时满足JA3和JA4的ClientHelloSpec
		spec := buildClientHelloSpecFromFingerprints(ja3String, ja4String, hostname)

		// 应用预设
		if err = uconn.ApplyPreset(spec); err != nil {
			return nil, nil, fmt.Errorf("应用预设失败: %w", err)
		}

		// 执行握手
		uTLSConn := &uTLSConn{uconn}
		err = uTLSConn.HandshakeContext(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("握手失败: %w", err)
		}

		cs := uconn.ConnectionState()
		conn = uTLSConn
		tlsState = &tls.ConnectionState{
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
		return
	}

	c.Transport.SetTLSHandshake(tlsHandshakeFn)
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
