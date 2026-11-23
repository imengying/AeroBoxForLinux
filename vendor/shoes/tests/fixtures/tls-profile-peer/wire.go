// A deliberately small, independent TLS 1.3 reference server for ALPS and
// certificate compression. Test-only: never used by AeroBox at runtime.
package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/andybalholm/brotli"
	"golang.org/x/crypto/hkdf"
)

func vector16(p []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(p))), p...)
}
func vector24(p []byte) []byte {
	return append([]byte{byte(len(p) >> 16), byte(len(p) >> 8), byte(len(p))}, p...)
}
func handshakeMessage(kind byte, body []byte) []byte { return append([]byte{kind}, vector24(body)...) }
func extension(id uint16, body []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, id), vector16(body)...)
}
func digest(p []byte) []byte { out := sha256.Sum256(p); return out[:] }
func expand(secret []byte, label string, context []byte, length int) []byte {
	name := []byte("tls13 " + label)
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(info, byte(len(name)))
	info = append(info, name...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	out := make([]byte, length)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, secret, info), out); err != nil {
		panic(err)
	}
	return out
}
func derive(secret []byte, label string, transcript []byte) []byte {
	return expand(secret, label, digest(transcript), 32)
}
func finished(secret, transcript []byte) []byte {
	hash := hmac.New(sha256.New, expand(secret, "finished", nil, 32))
	hash.Write(digest(transcript))
	return hash.Sum(nil)
}

type reader struct {
	p   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.p) {
		r.err = io.ErrUnexpectedEOF
		return nil
	}
	p := r.p[:n]
	r.p = r.p[n:]
	return p
}
func (r *reader) uint(n int) int {
	v := 0
	for _, b := range r.take(n) {
		v = v<<8 | int(b)
	}
	return v
}
func (r *reader) vector(n int) []byte { size := r.uint(n); return r.take(size) }
func (r *reader) done() error {
	if r.err != nil {
		return r.err
	}
	if len(r.p) != 0 {
		return errors.New("trailing bytes")
	}
	return nil
}
func extensions(body []byte) (map[uint16][]byte, error) {
	outer := reader{p: body}
	inner := reader{p: outer.vector(2)}
	if err := outer.done(); err != nil {
		return nil, err
	}
	out := map[uint16][]byte{}
	for len(inner.p) > 0 && inner.err == nil {
		id := uint16(inner.uint(2))
		value := inner.vector(2)
		if _, duplicate := out[id]; duplicate {
			return nil, errors.New("duplicate extension")
		}
		out[id] = value
	}
	return out, inner.done()
}
func has16(values []byte, wanted uint16) bool {
	if len(values)%2 != 0 {
		return false
	}
	for i := 0; i < len(values); i += 2 {
		if binary.BigEndian.Uint16(values[i:]) == wanted {
			return true
		}
	}
	return false
}

type protection struct {
	aead     cipher.AEAD
	iv       []byte
	sequence uint64
}

func protect(secret []byte) *protection {
	block, err := aes.NewCipher(expand(secret, "key", nil, 16))
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return &protection{aead: aead, iv: expand(secret, "iv", nil, 12)}
}
func (p *protection) nonce() []byte {
	iv := append([]byte(nil), p.iv...)
	for i := 0; i < 8; i++ {
		iv[len(iv)-1-i] ^= byte(p.sequence >> uint(8*i))
	}
	p.sequence++
	return iv
}
func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
func writePlain(w io.Writer, typ byte, payload []byte) error {
	return writeAll(w, append([]byte{typ, 3, 3}, vector16(payload)...))
}
func (p *protection) write(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > 16384 {
		return errors.New("reference record too large")
	}
	inner := append(append([]byte(nil), payload...), typ)
	header := binary.BigEndian.AppendUint16([]byte{23, 3, 3}, uint16(len(inner)+p.aead.Overhead()))
	return writeAll(w, append(header, p.aead.Seal(nil, p.nonce(), inner, header)...))
}
func readRecord(r io.Reader) (byte, []byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, nil, err
	}
	length := int(binary.BigEndian.Uint16(header[3:]))
	if length > 16640 {
		return 0, nil, nil, errors.New("oversized record")
	}
	body := make([]byte, length)
	_, err := io.ReadFull(r, body)
	return header[0], header, body, err
}
func (p *protection) read(r io.Reader) (byte, []byte, error) {
	for {
		typ, header, body, err := readRecord(r)
		if err != nil {
			return 0, nil, err
		}
		if typ == 20 && bytes.Equal(body, []byte{1}) {
			continue
		}
		if typ != 23 || !bytes.Equal(header[1:3], []byte{3, 3}) {
			return 0, nil, errors.New("expected encrypted record")
		}
		inner, err := p.aead.Open(nil, p.nonce(), body, header)
		if err != nil {
			return 0, nil, err
		}
		for len(inner) > 0 && inner[len(inner)-1] == 0 {
			inner = inner[:len(inner)-1]
		}
		if len(inner) == 0 {
			return 0, nil, errors.New("missing inner content type")
		}
		return inner[len(inner)-1], inner[:len(inner)-1], nil
	}
}

type messages struct{ bytes []byte }

func (m *messages) next(read func() (byte, []byte, error)) ([]byte, error) {
	for {
		if len(m.bytes) >= 4 {
			n := int(m.bytes[1])<<16 | int(m.bytes[2])<<8 | int(m.bytes[3])
			if n > 65537 {
				return nil, errors.New("oversized handshake")
			}
			if len(m.bytes) >= n+4 {
				result := append([]byte(nil), m.bytes[:n+4]...)
				m.bytes = m.bytes[n+4:]
				return result, nil
			}
		}
		typ, body, err := read()
		if err != nil {
			return nil, err
		}
		if typ != 22 {
			return nil, fmt.Errorf("expected handshake, received %d", typ)
		}
		m.bytes = append(m.bytes, body...)
		if len(m.bytes) > 131072 {
			return nil, errors.New("handshake buffer limit")
		}
	}
}

type peerOptions struct {
	UnadvertisedSignature  bool
	Reality                string
	RealityBrowser         bool
	UnadvertisedGroup      bool
	SCT                    string
	Group                  uint16
	ALPS                   uint16
	Compress               bool
	BadCertificateLength   bool
	BadFinished            bool
	ServerSettings         []byte
	ExpectedClientSettings []byte
	SelectedALPN           string
	OmitALPN               bool
	SkipALPSOfferCheck     bool
	BothALPS               bool
	UnsolicitedEarlyData   bool
	Tickets                *ticketStore
	EarlyMode              string
	AnyClientSettings      bool
	OversizedEE            bool
	CertificateLength      int
	TrailingCompressedData bool
	Mutual                 bool
	RotateServerSettings   bool
	ExpectedShares         []uint16
	CookieRetry            bool
	ForceRetry             bool
}
type peerResult struct {
	RealityAuthenticated bool   `json:"reality_authenticated"`
	Group                uint16 `json:"group"`
	HelloRetry           bool   `json:"hello_retry"`
	ALPS                 uint16 `json:"alps"`
	Compressed           bool   `json:"compressed"`
	ClientSettings       []byte `json:"client_settings"`
	Bytes                int    `json:"bytes"`
	Resumed              bool   `json:"resumed"`
	EarlyOffered         bool   `json:"early_offered"`
	EarlyAccepted        bool   `json:"early_accepted"`
}

func serveWire(conn net.Conn, certDER, keyDER []byte, options peerOptions) (result peerResult, err error) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	keyAny, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return result, err
	}
	private, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return result, errors.New("reference requires RSA fixture")
	}
	var stream messages
	readPlain := func() (byte, []byte, error) {
		for {
			typ, _, body, err := readRecord(conn)
			if err == nil && typ == 20 && bytes.Equal(body, []byte{1}) {
				continue
			}
			return typ, body, err
		}
	}
	ch, err := stream.next(readPlain)
	if err != nil {
		return result, err
	}
	hello, err := parseHello(ch)
	if err != nil {
		return result, err
	}
	var realityPrivate ed25519.PrivateKey
	if options.Reality != "" {
		certDER, realityPrivate, err = realityCredential(ch, hello, options.Reality, options.RealityBrowser)
		if err != nil {
			return result, err
		}
		result.RealityAuthenticated = true
	}
	if options.UnadvertisedSignature {
		certDER, realityPrivate, err = unadvertisedCertificate(certDER, private)
		if err != nil {
			return result, err
		}
	}
	if options.UnadvertisedGroup {
		if err = writePlain(conn, 22, helloRetry(hello.session, 25, false)); err != nil {
			return result, err
		}
		_, err = stream.next(readPlain)
		if err == nil {
			err = errors.New("client accepted unadvertised group")
		}
		return result, err
	}
	initialHello := append([]byte(nil), ch...)
	if options.ExpectedShares != nil {
		// Chrome adds a single, randomly selected GREASE share ahead of the
		// real key exchanges. Validate its position and dummy payload without
		// making callers predict the random reserved group identifier.
		shares := hello.shareOrder
		if len(shares) > 0 && shares[0]&0x0f0f == 0x0a0a && shares[0]>>8 == shares[0]&255 {
			if !bytes.Equal(hello.shares[shares[0]], []byte{0}) {
				return result, errors.New("invalid initial GREASE share")
			}
			shares = shares[1:]
		}
		if len(shares) != len(options.ExpectedShares) {
			return result, errors.New("wrong number of initial shares")
		}
		for i, group := range options.ExpectedShares {
			if shares[i] != group {
				return result, errors.New("wrong initial share order")
			}
		}
	}
	if hybrid, ok := hello.shares[0x11ec]; options.ExpectedShares != nil && ok && len(hybrid) == 1216 {
		if x, ok := hello.shares[29]; ok && bytes.Equal(x, hybrid[1184:]) {
			return result, errors.New("standalone X25519 reuses the hybrid private key")
		}
	}
	_, result.EarlyOffered = hello.extensions[42]
	group := options.Group
	if group == 0 {
		group = 29
	}
	result.Group = group
	var transcript []byte
	if _, ok := hello.shares[group]; !ok || options.CookieRetry || options.ForceRetry {
		groups := reader{p: hello.extensions[10]}
		if !has16(groups.vector(2), group) {
			return result, errors.New("requested group not supported")
		}
		hrr := helloRetry(hello.session, group, options.CookieRetry)
		transcript = append(handshakeMessage(254, digest(ch)), hrr...)
		if err = writePlain(conn, 22, hrr); err != nil {
			return result, err
		}
		ch, err = stream.next(readPlain)
		if err != nil {
			return result, err
		}
		next, err := parseHello(ch)
		if err != nil {
			return result, err
		}
		if !bytes.Equal(hello.session, next.session) || !bytes.Equal(hello.random, next.random) || !bytes.Equal(hello.ciphers, next.ciphers) {
			return result, errors.New("ClientHello changed immutable retry fields")
		}
		if options.CookieRetry {
			if !bytes.Equal(next.extensions[44], vector16([]byte("aerobox-cookie"))) || !bytes.Equal(next.extensions[51], hello.extensions[51]) {
				return result, errors.New("cookie-only retry changed shares or lost cookie")
			}
		} else if len(next.shares) != 1 {
			return result, errors.New("HRR response needs exactly one share")
		}
		hello = next
		result.HelloRetry = true
	}
	serverShare, shared, err := exchange(group, hello.shares[group])
	if err != nil {
		return result, err
	}
	previous, err := options.Tickets.selectPSK(ch, hello.extensions, transcript)
	if err != nil {
		return result, err
	}
	result.Resumed = previous != nil
	if previous != nil && options.RotateServerSettings {
		options.ServerSettings = append(append([]byte(nil), previous.serverSettings...), []byte(" next")...)
	}
	result.EarlyAccepted = result.EarlyOffered && !result.HelloRetry && previous != nil && options.EarlyMode == "accept" &&
		previous.alps == options.ALPS && bytes.Equal(previous.serverSettings, options.ServerSettings) &&
		(options.AnyClientSettings || bytes.Equal(previous.clientSettings, options.ExpectedClientSettings))
	exts := hello.extensions
	alpnList := reader{p: exts[16]}
	alpn := reader{p: alpnList.vector(2)}
	h2 := false
	for len(alpn.p) > 0 && alpn.err == nil {
		if bytes.Equal(alpn.vector(1), []byte("h2")) {
			h2 = true
		}
	}
	if !h2 {
		return result, errors.New("h2 not offered")
	}
	if options.ALPS != 0 && !options.SkipALPSOfferCheck {
		list := reader{p: exts[options.ALPS]}
		names := reader{p: list.vector(2)}
		found := false
		for len(names.p) > 0 && names.err == nil {
			if bytes.Equal(names.vector(1), []byte("h2")) {
				found = true
			}
		}
		if !found {
			return result, errors.New("requested ALPS h2 not offered")
		}
	}
	if options.Compress {
		list := reader{p: exts[27]}
		if !has16(list.vector(1), 2) {
			return result, errors.New("Brotli not offered")
		}
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return result, err
	}
	sh := serverHello(hello.session, random, append(binary.BigEndian.AppendUint16(nil, group), vector16(serverShare)...))
	if previous != nil {
		// ServerHello extensions are its final vector. Add selected_identity=0.
		pos := 4 + 2 + 32 + 1 + len(hello.session) + 2 + 1
		sh = handshakeMessage(2, append(append([]byte(nil), sh[4:pos]...), vector16(append(append([]byte(nil), sh[pos+2:]...), extension(41, []byte{0, 0})...))...))
	}
	transcript = append(transcript, ch...)
	transcript = append(transcript, sh...)
	if err = writePlain(conn, 22, sh); err != nil {
		return result, err
	}
	psk := make([]byte, 32)
	if previous != nil {
		psk = previous.secret
	}
	early := hkdf.Extract(sha256.New, psk, nil)
	var earlyKeys *protection
	if previous != nil && result.EarlyOffered {
		earlyKeys = protect(derive(early, "c e traffic", initialHello))
	}
	hs := hkdf.Extract(sha256.New, shared, derive(early, "derived", nil))
	clientHS := derive(hs, "c hs traffic", transcript)
	serverHS := derive(hs, "s hs traffic", transcript)
	serverKeys, clientKeys := protect(serverHS), protect(clientHS)
	writeHandshake := func(message []byte) error {
		for remaining := message; len(remaining) > 0; {
			n := min(len(remaining), 16384)
			if err := serverKeys.write(conn, 22, remaining[:n]); err != nil {
				return err
			}
			remaining = remaining[n:]
		}
		transcript = append(transcript, message...)
		return nil
	}
	alpnName := options.SelectedALPN
	if alpnName == "" {
		alpnName = "h2"
	}
	var ee []byte
	if !options.OmitALPN {
		ee = extension(16, vector16(append([]byte{byte(len(alpnName))}, []byte(alpnName)...)))
	}
	if options.ALPS != 0 && !result.EarlyAccepted {
		ee = append(ee, extension(options.ALPS, options.ServerSettings)...)
	}
	if options.BothALPS {
		other := uint16(17513)
		if options.ALPS == other {
			other = 17613
		}
		ee = append(ee, extension(other, nil)...)
	}
	if options.UnsolicitedEarlyData || result.EarlyAccepted {
		ee = append(ee, extension(42, nil)...)
	}
	eeMessage := handshakeMessage(8, vector16(ee))
	if options.OversizedEE {
		eeMessage[1], eeMessage[2], eeMessage[3] = 1, 0, 2
	}
	if err = writeHandshake(eeMessage); err != nil {
		return result, err
	}
	if !result.Resumed {
		if options.Mutual {
			request := append([]byte{0}, vector16(extension(13, vector16([]byte{8, 4})))...)
			if err = writeHandshake(handshakeMessage(13, request)); err != nil {
				return result, err
			}
		}
		var certificateExtensions []byte
		if options.SCT != "" {
			if _, ok := hello.extensions[18]; !ok {
				return result, errors.New("SCT not offered")
			}
			var timestamps []byte
			switch options.SCT {
			case "valid":
				timestamps = vector16(append(vector16([]byte("opaque timestamp one")), vector16([]byte("opaque timestamp two"))...))
			case "empty":
				timestamps = []byte{0, 0}
			case "empty-entry":
				timestamps = []byte{0, 2, 0, 0}
			case "trailing":
				timestamps = append(vector16(vector16([]byte("opaque timestamp"))), 0)
			default:
				return result, errors.New("unknown SCT mode")
			}
			certificateExtensions = extension(18, timestamps)
		}
		certificate := append([]byte{0}, vector24(append(vector24(certDER), vector16(certificateExtensions)...))...)
		certMessage := handshakeMessage(11, certificate)
		if options.Compress {
			var compressed bytes.Buffer
			writer := brotli.NewWriterLevel(&compressed, 5)
			if _, err = writer.Write(certificate); err != nil {
				return result, err
			}
			if err = writer.Close(); err != nil {
				return result, err
			}
			length := len(certificate)
			if options.BadCertificateLength {
				length++
			}
			if options.CertificateLength > 0 {
				length = options.CertificateLength
			}
			if options.TrailingCompressedData {
				compressed.WriteByte(0)
			}
			body := []byte{0, 2, byte(length >> 16), byte(length >> 8), byte(length)}
			certMessage = handshakeMessage(25, append(body, vector24(compressed.Bytes())...))
		}
		if err = writeHandshake(certMessage); err != nil {
			return result, err
		}
		verifyInput := append(bytes.Repeat([]byte{32}, 64), []byte("TLS 1.3, server CertificateVerify")...)
		verifyInput = append(verifyInput, 0)
		verifyInput = append(verifyInput, digest(transcript)...)
		var signature []byte
		scheme := []byte{8, 4}
		if realityPrivate != nil {
			signature = ed25519.Sign(realityPrivate, verifyInput)
			scheme = []byte{8, 7}
			if options.Reality == "bad-signature" {
				signature[0] ^= 1
			}
		} else {
			signature, err = rsa.SignPSS(rand.Reader, private, crypto.SHA256, digest(verifyInput), &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256})
			if err != nil {
				return result, err
			}
		}
		if err = writeHandshake(handshakeMessage(15, append(scheme, vector16(signature)...))); err != nil {
			return result, err
		}
	}
	verifyData := finished(serverHS, transcript)
	if options.BadFinished {
		verifyData[0] ^= 1
	}
	if err = writeHandshake(handshakeMessage(20, verifyData)); err != nil {
		return result, err
	}
	master := hkdf.Extract(sha256.New, make([]byte, 32), derive(hs, "derived", nil))
	serverApp, clientApp := protect(derive(master, "s ap traffic", transcript)), protect(derive(master, "c ap traffic", transcript))
	var earlyBytes []byte
	earlyRecords := 0
	readClientHandshake := func() (byte, []byte, error) {
		for {
			typ, header, body, err := readRecord(conn)
			if err != nil {
				return 0, nil, err
			}
			if typ == 20 && bytes.Equal(body, []byte{1}) {
				continue
			}
			if typ != 23 {
				return 0, nil, errors.New("expected protected client handshake")
			}
			sequence := clientKeys.sequence
			kind, payload, err := clientKeys.decrypt(header, body)
			if err == nil {
				return kind, payload, nil
			}
			clientKeys.sequence = sequence
			if !result.EarlyOffered || earlyRecords >= 256 {
				return 0, nil, err
			}
			earlyRecords++
			if !result.EarlyAccepted {
				continue
			}
			kind, payload, err = earlyKeys.decrypt(header, body)
			if err != nil {
				return 0, nil, err
			}
			if kind == 22 {
				return kind, payload, nil
			}
			if kind != 23 || len(earlyBytes)+len(payload) > 4096 {
				return 0, nil, errors.New("early data limit")
			}
			earlyBytes = append(earlyBytes, payload...)
		}
	}
	readHandshake := func() ([]byte, error) {
		return stream.next(readClientHandshake)
	}
	if result.EarlyAccepted {
		message, err := readHandshake()
		if err != nil {
			return result, err
		}
		if !bytes.Equal(message, []byte{5, 0, 0, 0}) {
			return result, errors.New("expected EndOfEarlyData")
		}
		transcript = append(transcript, message...)
		result.ClientSettings = append([]byte{}, previous.clientSettings...)
	}
	if options.ALPS != 0 && !result.EarlyAccepted {
		message, err := readHandshake()
		if err != nil {
			return result, err
		}
		if message[0] != 8 {
			return result, errors.New("missing client EncryptedExtensions")
		}
		clientExt, err := extensions(message[4:])
		if err != nil {
			return result, err
		}
		settings, present := clientExt[options.ALPS]
		if !present || len(clientExt) != 1 {
			return result, errors.New("invalid client ALPS extension")
		}
		if !options.AnyClientSettings && !bytes.Equal(settings, options.ExpectedClientSettings) {
			return result, fmt.Errorf("unexpected client settings %x", settings)
		}
		result.ClientSettings = append([]byte{}, settings...)
		transcript = append(transcript, message...)
	}
	if options.Mutual && !result.Resumed {
		transcript, err = authenticateClient(readHandshake, transcript, certDER)
		if err != nil {
			return result, err
		}
	}
	clientFinished, err := readHandshake()
	if err != nil {
		return result, err
	}
	if clientFinished[0] != 20 || !hmac.Equal(clientFinished[4:], finished(clientHS, transcript)) {
		return result, errors.New("invalid client Finished/transcript")
	}
	if len(stream.bytes) != 0 {
		return result, errors.New("unexpected extra client handshake")
	}
	transcript = append(transcript, clientFinished...)
	if options.Tickets != nil {
		options.ExpectedClientSettings = result.ClientSettings
		message := options.Tickets.issue(master, transcript, options, options.EarlyMode != "")
		if err = serverApp.write(conn, 22, message); err != nil {
			return result, err
		}
	}
	result.ALPS = options.ALPS
	result.Compressed = options.Compress && !result.Resumed
	if len(earlyBytes) > 0 {
		result.Bytes += len(earlyBytes)
		if err = serverApp.write(conn, 23, earlyBytes); err != nil {
			return result, err
		}
	}
	for {
		typ, payload, err := clientApp.read(conn)
		if err != nil {
			return result, err
		}
		if typ == 21 && bytes.Equal(payload, []byte{1, 0}) {
			return result, serverApp.write(conn, 21, []byte{1, 0})
		}
		if typ != 23 {
			return result, fmt.Errorf("unexpected post-handshake type %d", typ)
		}
		result.Bytes += len(payload)
		if err = serverApp.write(conn, 23, payload); err != nil {
			return result, err
		}
	}
}
