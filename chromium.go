package mimic

import (
	"errors"
	"strconv"
	"strings"

	"github.com/miromiro11/fhttp/http2"
	utls "github.com/miromiro11/utls"
)

var (
	ErrUnsupportedVersion = errors.New("mimic: unsupported version")
)

func getMajor(version string) (string, int, error) {
	major := strings.SplitN(version, ".", 2)[0]
	iMajor, err := strconv.Atoi(major)	
	return major, iMajor, err
}

func Chromium(brand Brand, version string, Ja3 string) (*ClientSpec, error) {

	major, iMajor, err := getMajor(version)

	if err != nil {
		return nil, err
	}

	if Ja3 != "" {
		tlsHello,err := MatchJa3String(Ja3)
		if err != nil {
			return nil, err
		}
		return &ClientSpec{
			version:      version,
			clientHintUA: clientHintUA(iMajor, brand, major, version),
			h2Options: &http2Options{
				Settings: []http2.Setting{
					{ID: http2.SettingEnablePush, Val: 1},
					{ID: http2.SettingMaxConcurrentStreams, Val: 100},
					{ID: http2.SettingInitialWindowSize, Val: 65535},
					{ID: http2.SettingMaxFrameSize, Val: 16384},
					{ID: http2.SettingMaxHeaderListSize, Val: 65536},
				},
				PseudoHeaderOrder: []string{
					":authority",
					":method",
					":path",
					":scheme",
					":status",
				},
				MaxHeaderListSize: 65536,
				InitialWindowSize: 65535,
				HeaderTableSize:   4096,
			},
			getTlsSpec: func() *utls.ClientHelloSpec {
				return &tlsHello
			},
		}, nil
	}else if iMajor >= 100{
		return &ClientSpec{
			version,
			clientHintUA(iMajor, brand, major, version),
			&http2Options{
				PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
				MaxHeaderListSize: 262144,
				Settings: []http2.Setting{
					{ID: http2.SettingHeaderTableSize, Val: 65536},
					{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
					{ID: http2.SettingInitialWindowSize, Val: 6291456},
					{ID: http2.SettingMaxHeaderListSize, Val: 262144},
				},
				InitialWindowSize: 6291456,
				HeaderTableSize:   65536,
			},
			func() *utls.ClientHelloSpec {
				return &utls.ClientHelloSpec{
					CipherSuites: []uint16{
						utls.GREASE_PLACEHOLDER,
						utls.TLS_AES_128_GCM_SHA256,
						utls.TLS_AES_256_GCM_SHA384,
						utls.TLS_CHACHA20_POLY1305_SHA256,
						utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
						utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
						utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						utls.TLS_RSA_WITH_AES_128_CBC_SHA,
						utls.TLS_RSA_WITH_AES_256_CBC_SHA,
					},
					CompressionMethods: []byte{
						0x00, // compressionNone
					},
					Extensions: []utls.TLSExtension{
						&utls.UtlsGREASEExtension{},
						&utls.SNIExtension{},
						&utls.UtlsExtendedMasterSecretExtension{},
						&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
						&utls.SupportedCurvesExtension{
							Curves: []utls.CurveID{
								utls.CurveID(utls.GREASE_PLACEHOLDER),
								utls.X25519,
								utls.CurveP256,
								utls.CurveP384,
							}},
						&utls.SupportedPointsExtension{SupportedPoints: []byte{
							0x00, // pointFormatUncompressed
						}},
						&utls.SessionTicketExtension{},
						&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
						&utls.StatusRequestExtension{},
						&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
							utls.ECDSAWithP256AndSHA256,
							utls.PSSWithSHA256,
							utls.PKCS1WithSHA256,
							utls.ECDSAWithP384AndSHA384,
							utls.PSSWithSHA384,
							utls.PKCS1WithSHA384,
							utls.PSSWithSHA512,
							utls.PKCS1WithSHA512,
						}},
						&utls.SCTExtension{},
						&utls.KeyShareExtension{
							KeyShares: []utls.KeyShare{
								{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
								{Group: utls.X25519},
							}},
						&utls.PSKKeyExchangeModesExtension{
							Modes: []uint8{
								utls.PskModeDHE,
							}},
						&utls.SupportedVersionsExtension{
							Versions: []uint16{
								utls.GREASE_PLACEHOLDER,
								utls.VersionTLS13,
								utls.VersionTLS12,
							}},
						&utls.UtlsCompressCertExtension{
							Methods: []utls.CertCompressionAlgo{
								utls.CertCompressionBrotli,
							}},
						&utls.ALPSExtension{SupportedProtocols: []string{"h2"}},
						&utls.UtlsGREASEExtension{},
						&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
					},
				}
			},
		}, nil
		}
	return nil, ErrUnsupportedVersion
}
