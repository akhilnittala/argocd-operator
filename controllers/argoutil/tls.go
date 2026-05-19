// Copyright 2019 ArgoCD Operator Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package argoutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	argoproj "github.com/argoproj-labs/argocd-operator/api/v1beta1"
	"github.com/argoproj-labs/argocd-operator/common"
)

// NewPrivateKey returns randomly generated RSA private key.
func NewPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, common.ArgoCDDefaultRSAKeySize)
}

// EncodePrivateKeyPEM encodes the given private key pem and returns bytes (base64).
func EncodePrivateKeyPEM(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// EncodeCertificatePEM encodes the given certificate pem and returns bytes (base64).
func EncodeCertificatePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// ParsePEMEncodedCert parses a certificate from the given pemdata
func ParsePEMEncodedCert(pemdata []byte) (*x509.Certificate, error) {
	decoded, _ := pem.Decode(pemdata)
	if decoded == nil {
		return nil, errors.New("no PEM data found")
	}
	return x509.ParseCertificate(decoded.Bytes)
}

// ParsePEMEncodedPrivateKey parses a private key from given pemdata
func ParsePEMEncodedPrivateKey(pemdata []byte) (*rsa.PrivateKey, error) {
	decoded, _ := pem.Decode(pemdata)
	if decoded == nil {
		return nil, errors.New("no PEM data found")
	}
	return x509.ParsePKCS1PrivateKey(decoded.Bytes)
}

// NewSelfSignedCACertificate returns a self-signed CA certificate based on given configuration and private key.
// The certificate has one-year lease.
func NewSelfSignedCACertificate(name string, key *rsa.PrivateKey) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             now.UTC(),
		NotAfter:              now.Add(common.ArgoCDDuration365Days).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		Subject:               pkix.Name{CommonName: fmt.Sprintf("argocd-operator@%s", name)},
	}
	certDERBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDERBytes)
}

// NewSignedCertificate signs a certificate using the given private key, CA and returns a signed certificate.
// The certificate could be used for both client and server auth.
// The certificate has one-year lease.
func NewSignedCertificate(cfg *certmanagerv1.CertificateSpec, dnsNames []string, key *rsa.PrivateKey, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	eku := []x509.ExtKeyUsage{}
	eku = append(eku, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth)
	certTmpl := x509.Certificate{
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: cfg.Subject.Organizations,
		},
		DNSNames:     dnsNames,
		SerialNumber: serial,
		NotBefore:    caCert.NotBefore,
		NotAfter:     time.Now().Add(common.ArgoCDDuration365Days).UTC(),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
	}
	certDERBytes, err := x509.CreateCertificate(rand.Reader, &certTmpl, caCert, key.Public(), caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDERBytes)
}

// -------------------- TLS Version Maps --------------------

var (
	supportedTLSVersions = map[string]uint16{
		"1.1": tls.VersionTLS11,
		"1.2": tls.VersionTLS12,
		"1.3": tls.VersionTLS13,
	}
	tlsVersionNames = map[uint16]string{
		tls.VersionTLS11: "1.1",
		tls.VersionTLS12: "1.2",
		tls.VersionTLS13: "1.3",
	}
	// Precompute once instead of every validation call
	supportedCipherSuites = buildCipherSuiteMap()
)

func buildCipherSuiteMap() map[string]*tls.CipherSuite {
	m := make(map[string]*tls.CipherSuite)
	for _, cs := range tls.CipherSuites() {
		m[cs.Name] = cs
	}
	return m
}

// -------------------- TLS Version Helpers --------------------

func TLSVersionName(version uint16) string {
	if name, ok := tlsVersionNames[version]; ok {
		return name
	}
	return fmt.Sprintf("unknown (0x%04x)", version)
}

func ParseTLSVersion(v string) (uint16, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	val, ok := supportedTLSVersions[v]
	if !ok {
		return 0, fmt.Errorf("invalid TLS version %q: supported values are 1.1, 1.2, 1.3", v)
	}
	return val, nil
}

// -------------------- TLS Validation --------------------

func ValidateTLSConfig(minVersion, maxVersion uint16, cipherSuites []string) error {
	// Validate version range
	if minVersion != 0 && maxVersion != 0 && minVersion > maxVersion {
		return fmt.Errorf("minimum TLS version (%s) cannot be higher than maximum TLS version (%s)", TLSVersionName(minVersion), TLSVersionName(maxVersion))
	}
	// No cipher validation needed
	if len(cipherSuites) == 0 {
		return nil
	}
	for _, name := range cipherSuites {
		name = strings.TrimSpace(name)
		cs, ok := supportedCipherSuites[name]
		if !ok {
			return fmt.Errorf("unsupported cipher suite: %s", name)
		}
		// TLS 1.3 ciphers don't need compatibility validation
		if minVersion == tls.VersionTLS13 {
			continue
		}

		if !isCipherCompatible(cs, minVersion, maxVersion) {
			return fmt.Errorf("cipher suite %s is not compatible with TLS versions [%s - %s]", name, TLSVersionName(minVersion), TLSVersionName(maxVersion))
		}
	}
	return nil
}

func isCipherCompatible(cs *tls.CipherSuite, minVersion, maxVersion uint16) bool {
	for _, v := range cs.SupportedVersions {
		if (minVersion == 0 || v >= minVersion) && (maxVersion == 0 || v <= maxVersion) {
			return true
		}
	}
	return false
}

func validateAndParseTLS(tlsCfg *argoproj.ArgoCDTlsConfig) (uint16, uint16, error) {
	if tlsCfg == nil {
		return 0, 0, nil
	}
	minVer, err := ParseTLSVersion(tlsCfg.MinVersion)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid min TLS version: %w", err)
	}
	maxVer, err := ParseTLSVersion(tlsCfg.MaxVersion)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid max TLS version: %w", err)
	}
	if err := ValidateTLSConfig(minVer, maxVer, tlsCfg.CipherSuites); err != nil {
		return 0, 0, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	return minVer, maxVer, nil
}

func JoinCiphers(cipherSuites []string) string {
	if len(cipherSuites) == 0 {
		return ""
	}
	return strings.Join(cipherSuites, ":")
}

// -------------------- Argo CD Agent TLS Args --------------------

func agentTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS11:
		return "tls1.1"
	case tls.VersionTLS12:
		return "tls1.2"
	case tls.VersionTLS13:
		return "tls1.3"
	default:
		return ""
	}
}

func BuildArgoCDAgentTLSArgs(tlsCfg *argoproj.ArgoCDTlsConfig, args map[string]string) (map[string]string, error) {
	minVer, maxVer, err := ResolveTLSConfig(tlsCfg)
	if err != nil {
		return nil, err
	}
	args["--tlsminversion"] = agentTLSVersion(minVer)
	args["--tlsmaxversion"] = agentTLSVersion(maxVer)
	if tlsCfg != nil {
		if ciphers := JoinCiphers(tlsCfg.CipherSuites); ciphers != "" {
			args["--tlsciphers"] = ciphers
		}
	}
	return args, nil
}

// -------------------- Redis TLS Args --------------------

func redisTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLSv1"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return ""
	}
}

func MapRedisTLSVersionFromTLSProfileValues(v configv1.TLSProtocolVersion) string {
	switch v {
	case configv1.VersionTLS10:
		return "TLSv1"
	case configv1.VersionTLS11:
		return "TLSv1.1"
	case configv1.VersionTLS12:
		return "TLSv1.2"
	case configv1.VersionTLS13:
		return "TLSv1.3"
	default:
		return ""
	}
}

func MapArgoCDComponentsTLSVersionFromTLSProfileValues(v configv1.TLSProtocolVersion) string {
	switch v {
	case configv1.VersionTLS10:
		return "1.0"
	case configv1.VersionTLS11:
		return "1.1"
	case configv1.VersionTLS12:
		return "1.2"
	case configv1.VersionTLS13:
		return "1.3"
	default:
		return ""
	}
}

func BuildRedisProtocols(minVersion, maxVersion uint16) []string {
	order := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}
	var protocols []string
	started := false
	for _, v := range order {
		if v == minVersion {
			started = true
		}
		if started {
			protocols = append(protocols, redisTLSVersion(v))
		}
		if v == maxVersion {
			break
		}
	}
	return protocols
}

func ResolveTLSConfig(tlsCfg *argoproj.ArgoCDTlsConfig) (uint16, uint16, error) {
	minVer, maxVer, err := validateAndParseTLS(tlsCfg)
	if err != nil {
		return 0, 0, err
	}
	if maxVer == 0 {
		maxVer = tls.VersionTLS13 // sane default
	}
	return minVer, maxVer, nil
}

func MapCipherSuites(names []string) []string {
	m := map[string]string{
		"TLS_AES_128_GCM_SHA256":       "TLS_AES_128_GCM_SHA256",       // 0x13,0x01
		"TLS_AES_256_GCM_SHA384":       "TLS_AES_256_GCM_SHA384",       // 0x13,0x02
		"TLS_CHACHA20_POLY1305_SHA256": "TLS_CHACHA20_POLY1305_SHA256", // 0x13,0x03

		// TLS 1.2
		"ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",       // 0xC0,0x2B
		"ECDHE-RSA-AES128-GCM-SHA256":   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",         // 0xC0,0x2F
		"ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",       // 0xC0,0x2C
		"ECDHE-RSA-AES256-GCM-SHA384":   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",         // 0xC0,0x30
		"ECDHE-ECDSA-CHACHA20-POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", // 0xCC,0xA9
		"ECDHE-RSA-CHACHA20-POLY1305":   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",   // 0xCC,0xA8
		//"ECDHE-ECDSA-AES128-SHA256":     "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",       // 0xC0,0x23
		//"ECDHE-RSA-AES128-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", // 0xC0,0x27
		//"AES128-GCM-SHA256": "TLS_RSA_WITH_AES_128_GCM_SHA256", // 0x00,0x9C
		//"AES256-GCM-SHA384": "TLS_RSA_WITH_AES_256_GCM_SHA384", // 0x00,0x9D
		//"AES128-SHA256":     "TLS_RSA_WITH_AES_128_CBC_SHA256", // 0x00,0x3C

		// Go's crypto/tls does not support CBC mode and DHE ciphers, so we don't want to include them here.
		// See:
		//   - https://github.com/golang/go/issues/26652
		//   - https://github.com/golang/go/issues/7758
		// "ECDHE-ECDSA-AES256-SHA384":     "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",       // 0xC0,0x24
		// "ECDHE-RSA-AES256-SHA384":       "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",         // 0xC0,0x28
		// "AES256-SHA256":                 "TLS_RSA_WITH_AES_256_CBC_SHA256",               // 0x00,0x3D
		// "DHE-RSA-AES128-GCM-SHA256":     "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",           // 0x00,0x9E
		// "DHE-RSA-AES256-GCM-SHA384":     "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",           // 0x00,0x9F
		// "DHE-RSA-CHACHA20-POLY1305":     "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",     // 0xCC,0xAA
		// "DHE-RSA-AES128-SHA256":         "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",           // 0x00,0x67
		// "DHE-RSA-AES256-SHA256":         "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",           // 0x00,0x6B

		// TLS 1
		//"ECDHE-ECDSA-AES128-SHA": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", // 0xC0,0x09
		//"ECDHE-RSA-AES128-SHA":   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",   // 0xC0,0x13
		//"ECDHE-ECDSA-AES256-SHA": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", // 0xC0,0x0A
		//"ECDHE-RSA-AES256-SHA":   "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",   // 0xC0,0x14

		// SSL 3
		//"AES128-SHA":             "TLS_RSA_WITH_AES_128_CBC_SHA",        // 0x00,0x2F
		//"AES256-SHA":             "TLS_RSA_WITH_AES_256_CBC_SHA",        // 0x00,0x35
		//"DES-CBC3-SHA":           "TLS_RSA_WITH_3DES_EDE_CBC_SHA",       // 0x00,0x0A
		//"ECDHE-RSA-DES-CBC3-SHA": "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", // 0xC0,0x12
	}

	out := make([]string, 0, len(names))
	for _, name := range names {
		if mapped, ok := m[name]; ok {
			out = append(out, mapped)
		}
	}
	return out
}
