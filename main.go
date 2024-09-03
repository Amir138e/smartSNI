package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"github.com/valyala/fasthttp"
	"golang.org/x/time/rate"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	// BufferPool for reuse of byte slices
	BufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 4096) // Adjust the size according to your needs
		},
	}
	config  *Config
	limiter *rate.Limiter
)

// Config represents the structure of the configuration file.
type Config struct {
	Host    string            `json:"host"`
	Domains map[string]string `json:"domains"`
}

// LoadConfig loads the configuration from a JSON file.
func LoadConfig(filename string) (*Config, error) {
	var config Config
	cfgBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(cfgBytes, &config)
	return &config, err
}

func findValueByKeyContains(m map[string]string, substr string) (string, bool) {
	for key, value := range m {
		if strings.Contains(strings.ToLower(substr), strings.ToLower(key)) {
			return value, true
		}
	}
	return "", false // Return empty string and false if no key contains the substring
}

// processDNSQuery processes the DNS query and returns a response.
func processDNSQuery(query []byte) ([]byte, error) {
	var msg dns.Msg
	err := msg.Unpack(query)
	if err != nil {
		return nil, err
	}

	if len(msg.Question) == 0 {
		return nil, fmt.Errorf("no DNS question found in the request")
	}

	domain := msg.Question[0].Name
	if ip, ok := findValueByKeyContains(config.Domains, domain); ok {
		hdr := dns.RR_Header{
			Name:   domain,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    3600, // example TTL
		}
		rr := &dns.A{
			Hdr: hdr,
			A:   net.ParseIP(ip),
		}
		if rr.A == nil {
			return nil, fmt.Errorf("invalid IP address")
		}
		msg.Answer = append(msg.Answer, rr)
		msg.SetReply(&msg) // Set appropriate flags and sections
		return msg.Pack()
	}

	resp, err := http.Post("https://1.1.1.1/dns-query", "application/dns-message", bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Use a fixed-size buffer from the pool for the initial read
	buffer := BufferPool.Get().([]byte)
	defer BufferPool.Put(buffer)

	// Read the initial chunk of the response
	n, err := resp.Body.Read(buffer)
	if err != nil && err != io.EOF {
		return nil, err
	}

	// If the buffer was large enough to hold the entire response, return it
	if n < len(buffer) {
		return buffer[:n], nil
	}

	// If the response is larger than our buffer, we need to read the rest
	// and append to a dynamically-sized buffer
	var dynamicBuffer bytes.Buffer
	dynamicBuffer.Write(buffer[:n])
	_, err = dynamicBuffer.ReadFrom(resp.Body)
	if err != nil {
		return nil, err
	}

	return dynamicBuffer.Bytes(), nil
}

// handleDoTConnection handles a single DoT connection.
func handleDoTConnection(conn net.Conn) {
	defer conn.Close()

	if !limiter.Allow() {
		log.Println("limit exceeded")
		return
	}

	// Use a fixed-size buffer from the pool for the initial read
	poolBuffer := BufferPool.Get().([]byte)
	defer BufferPool.Put(poolBuffer)

	// Read the first two bytes to determine the length of the DNS message
	_, err := io.ReadFull(conn, poolBuffer[:2])
	if err != nil {
		log.Println(err)
		return
	}

	// Parse the length of the DNS message
	dnsMessageLength := binary.BigEndian.Uint16(poolBuffer[:2])

	// Prepare a buffer to read the full DNS message
	var buffer []byte
	if int(dnsMessageLength) > len(poolBuffer) {
		// If pool buffer is too small, allocate a new buffer
		buffer = make([]byte, dnsMessageLength)
	} else {
		// Use the pool buffer directly
		buffer = poolBuffer[:dnsMessageLength]
	}

	// Read the DNS message
	_, err = io.ReadFull(conn, buffer)
	if err != nil {
		log.Println(err)
		return
	}

	// Process the DNS query and generate a response
	response, err := processDNSQuery(buffer)
	if err != nil {
		log.Println(err)
		return
	}

	// Prepare the response with the length header
	responseLength := make([]byte, 2)
	binary.BigEndian.PutUint16(responseLength, uint16(len(response)))

	// Write the length of the response followed by the response itself
	_, err = conn.Write(responseLength)
	if err != nil {
		log.Println(err)
		return
	}

	_, err = conn.Write(response)
	if err != nil {
		log.Println(err)
		return
	}
}

// startDoTServer starts the DNS-over-TLS server.
func startDoTServer() {
	// Load TLS credentials
	certPrefix := "/etc/letsencrypt/live/" + config.Host + "/"
	cer, err := tls.LoadX509KeyPair(certPrefix+"/fullchain.pem", certPrefix+"privkey.pem")
	if err != nil {
		log.Fatal(err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cer}}

	listener, err := tls.Listen("tcp", ":853", tlsConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleDoTConnection(conn)
	}
}

func serveSniProxy() {
	l, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn)
	}
}

func peekClientHello(reader io.Reader) (*tls.ClientHelloInfo, io.Reader, error) {
	peekedBytes := new(bytes.Buffer)
	hello, err := readClientHello(io.TeeReader(reader, peekedBytes))
	if err != nil {
		return nil, nil, err
	}
	return hello, peekedBytes, nil
}

type readOnlyConn struct {
	reader io.Reader
}

func (conn readOnlyConn) Read(p []byte) (int, error)         { return conn.reader.Read(p) }
func (conn readOnlyConn) Write(_ []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (conn readOnlyConn) Close() error                       { return conn.Close() }
func (conn readOnlyConn) LocalAddr() net.Addr                { return nil }
func (conn readOnlyConn) RemoteAddr() net.Addr               { return nil }
func (conn readOnlyConn) SetDeadline(t time.Time) error      { return conn.SetDeadline(t) }
func (conn readOnlyConn) SetReadDeadline(t time.Time) error  { return conn.SetReadDeadline(t) }
func (conn readOnlyConn) SetWriteDeadline(t time.Time) error { return conn.SetWriteDeadline(t) }

func readClientHello(reader io.Reader) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo
	var wg sync.WaitGroup

	// Set the wait group for one operation (Handshake)
	wg.Add(1)

	config := &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = argHello // Capture the ClientHelloInfo
			wg.Done()        // Indicate that the handshake is complete
			return nil, nil
		},
	}

	tlsConn := tls.Server(readOnlyConn{reader: reader}, config)
	err := tlsConn.Handshake()

	// Wait for the handshake to be captured
	wg.Wait()

	if hello == nil {
		return nil, err
	}

	return hello, nil
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		log.Println(err)
		return
	}

	clientHello, clientHelloBytes, err := peekClientHello(clientConn)
	if err != nil {
		log.Println(err)
		return
	}

	if strings.TrimSpace(clientHello.ServerName) == "" {
		log.Println("empty sni not allowed here")
		// HTTP response headers and body
		response := "HTTP/1.1 502 OK\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n" +
			"Content-Length: 13\r\n" +
			"\r\n" +
			"Hello, world!"

		// Send the response to the client
		clientConn.Write([]byte(response))

		return
	}

	target := clientHello.ServerName + ":443"

	serverConn, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		log.Println(err)
		return
	}
	defer serverConn.Close()

	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		log.Println(err)
		return
	}

	if _, err := io.Copy(serverConn, clientHelloBytes); err != nil {
		log.Println(err)
		return
	}

	go func() {
		if _, err := io.Copy(serverConn, clientConn); err != nil {
			log.Println(err)
		}
	}()

	if _, err := io.Copy(clientConn, serverConn); err != nil {
		log.Println(err)
	}
}

func dohHandler(ctx *fasthttp.RequestCtx) {
	if string(ctx.Method()) == http.MethodPost || string(ctx.Method()) == http.MethodGet {
		ctx.Response.Header.Set("Content-Type", "application/dns-message")
		if string(ctx.Method()) == http.MethodGet {
			request := ctx.FormValue("dns")
			requestBinary, err := base64.RawURLEncoding.DecodeString(string(request))
			if err != nil {
				ctx.Error("invalid request", fasthttp.StatusBadRequest)
				return
			}
			response, err := processDNSQuery(requestBinary)
			if err != nil {
				ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
				return
			}
			ctx.SetBody(response)
			return
		}

		response, err := processDNSQuery(ctx.PostBody())
		if err != nil {
			ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
			return
		}

		ctx.SetBody(response)
		return
	}
	ctx.Error("not found", fasthttp.StatusNotFound)
}

func runDOHServer() {
	server := &fasthttp.Server{
		Handler:        dohHandler,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		MaxConnsPerIP:  10,
		MaxRequestBodySize: 512,
	}

	certPrefix := "/etc/letsencrypt/live/" + config.Host + "/"

	tlsConfig := &tls.Config{
		PreferServerCipherSuites: true,
		Certificates: []tls.Certificate{loadTLSCertificate(certPrefix + "fullchain.pem", certPrefix + "privkey.pem")},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	log.Println("Starting DoH server on :443/dns-query")
	err := server.ListenAndServeTLS(":443", certPrefix+"fullchain.pem", certPrefix+"privkey.pem")
	if err != nil {
		log.Fatalf("Error starting DoH server: %v", err)
	}
}

// loadTLSCertificate loads a TLS certificate from the specified files.
func loadTLSCertificate(certFile, keyFile string) tls.Certificate {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Error loading TLS certificate: %v", err)
	}
	return cert
}

// DNS handler for standard DNS queries (port 53).
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	domain := r.Question[0].Name

	if ip, ok := findValueByKeyContains(config.Domains, domain); ok {
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   domain,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			A: net.ParseIP(ip),
		}
		msg.Answer = append(msg.Answer, rr)
	} else {
		msg.SetRcode(r, dns.RcodeNameError) // Return NXDOMAIN if domain not found
	}

	w.WriteMsg(msg)
}

// startDNSServer starts the standard DNS server on port 53.
func startDNSServer() {
	dns.HandleFunc(".", handleDNSRequest)
	server := &dns.Server{Addr: ":53", Net: "udp"}
	log.Printf("Starting DNS server on :53...")
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start DNS server: %s\n", err.Error())
	}
}

func main() {
	err := os.Setenv("GOGC", "50")
	if err != nil {
		log.Fatal(err)
	} // Set GOGC to 50 to make GC more aggressive

	cfg, err := LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	config = cfg

	log.Println("Starting servers...")

	var wg sync.WaitGroup
	wg.Add(4)

	limiter = rate.NewLimiter(10, 50) // 1 request per second with a burst size of 5

	go func() {
		runDOHServer()
		wg.Done()
	}()
	go func() {
		startDoTServer()
		wg.Done()
	}()
	go func() {
		serveSniProxy()
		wg.Done()
	}()
	go func() {
		startDNSServer() // Start the standard DNS server
		wg.Done()
	}()

	wg.Wait()
}
