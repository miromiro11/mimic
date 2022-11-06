package mimic

import (
	"strconv"
	"strings"

	utls "github.com/miromiro11/utls"
)

func GenMap(curves []utls.CurveID)map[string]utls.TLSExtension{
	return map[string]utls.TLSExtension{
		"0": &utls.SNIExtension{},
		"5": &utls.StatusRequestExtension{},
		"13": &utls.SignatureAlgorithmsExtension{
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
		},
		"16": &utls.ALPNExtension{
			AlpnProtocols: []string{"h2", "http/1.1"},
		},
		"17": &utls.GenericExtension{Id: 17}, // status_request_v2
		"18": &utls.SCTExtension{},
		"21": &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		"22": &utls.GenericExtension{Id: 22}, // encrypt_then_mac
		"23": &utls.UtlsExtendedMasterSecretExtension{},
		"27": &utls.UtlsCompressCertExtension{
			Methods: []utls.CertCompressionAlgo{utls.CertCompressionBrotli},
		},
		"28": &utls.FakeRecordSizeLimitExtension{}, //Limit: 0x4001
		"35": &utls.SessionTicketExtension{},
		"34": &utls.GenericExtension{Id: 34},
		"41": &utls.GenericExtension{Id: 41},
		"43": &utls.SupportedVersionsExtension{Versions: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.VersionTLS13,
			utls.VersionTLS12,
		}},
		"44": &utls.CookieExtension{},
		"45": &utls.PSKKeyExchangeModesExtension{Modes: []uint8{
			utls.PskModeDHE,
		}},
		"49": &utls.GenericExtension{Id: 49}, // post_handshake_auth
		"50": &utls.GenericExtension{Id: 50}, // signature_algorithms_cert
		"51": &utls.KeyShareExtension{
			KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519},
		}},
		"30032": &utls.GenericExtension{Id: 0x7550, Data: []byte{0}}, //FIXME
		"13172": &utls.NPNExtension{},
		"17513": &utls.ALPSExtension{
			SupportedProtocols: []string{"h2"},
		},
		"65281": &utls.RenegotiationInfoExtension{
			Renegotiation: utls.RenegotiateOnceAsClient,
		},
		"10": &utls.SupportedCurvesExtension{
			Curves: curves,
		},
		"11": &utls.SupportedPointsExtension{
			SupportedPoints: []uint8{
				0x00,
		}},
		"15": &utls.GenericExtension{Id: 15}, // ec_point_formats
	}
}
//4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53
var TlsCipherMap = map[string]uint16{
	"4865": utls.TLS_AES_128_GCM_SHA256,
	"4866": utls.TLS_AES_256_GCM_SHA384,
	"4867": utls.TLS_CHACHA20_POLY1305_SHA256,
	"49195": utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"49199": utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"49196": utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"49200": utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"52393": utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	"52392": utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	"49188": utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	"49171": utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"49172": utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"156": utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"157": utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"47": utls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"53": utls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"49162": utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"49161": utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"51": utls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	"43": utls.TLS_KRB5_EXPORT_WITH_RC4_40_MD5,
	"57": utls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	"10": utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	"49187": utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"49192": utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	"49191": utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"61": utls.TLS_RSA_WITH_AES_256_CBC_SHA256,
	"60": utls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	"49160": utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	"49170": utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
}


func MatchJa3String(ja3 string) (utls.ClientHelloSpec, error) {
	splitted := strings.Split(ja3, ",")
	extensionsWanted := []utls.TLSExtension{}
	Cipher := splitted[1]
	Extensions := splitted[2]
	EllipticCurvesString := splitted[3]
	EllipticCurves := []utls.CurveID{}
	// log.Println("Cipher", Cipher)
	// log.Println("Extensions", Extensions)
	// log.Println("EllipticCurves", EllipticCurvesString)
	for _, curve := range strings.Split(EllipticCurvesString, "-") {
		inted, err := strconv.Atoi(curve)
		if err != nil {
			return utls.ClientHelloSpec{}, err
		}
		EllipticCurves = append(EllipticCurves, utls.CurveID(inted))
	}
	TLSExtensionMap := GenMap(EllipticCurves)
	for _, extension := range strings.Split(Extensions, "-") {
		if _, ok := TLSExtensionMap[extension]; ok {
			extensionsWanted = append(extensionsWanted, TLSExtensionMap[extension])
		}
	}
	Ciphers := []uint16{}
	for _, cipher := range strings.Split(Cipher, "-") {
		if _, ok := TlsCipherMap[cipher]; ok {
			Ciphers = append(Ciphers, TlsCipherMap[cipher])
		}
	}
	customClientSpecification := utls.ClientHelloSpec{
		CipherSuites: Ciphers,
		CompressionMethods: []byte{
			0x00, // compressionNone
		},
		Extensions:   extensionsWanted,
	}
	return customClientSpecification, nil
}