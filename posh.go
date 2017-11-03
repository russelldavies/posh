/*
posh: Printing Over Simple HTTP
*/
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"
)

const AppVersion = "1.1.0"

var (
	username      = flag.String("username", "", "posh username")
	password      = flag.String("password", "", "posh password")
	port          = flag.Int("port", 443, "Port that posh listens on")
	silent        = flag.Bool("s", false, "Silent; do not output anything")
	showTimestamp = flag.Bool("t", false, "Show timestamp; include timestamp in log messages")
	version       = flag.Bool("version", false, "Print version")
	addr          string
	hostname      = "posh"

	stats          map[string]int64 = make(map[string]int64)
	statsDurations                  = map[string]time.Duration{
		"day":   time.Hour * 24,
		"week":  time.Hour * 24 * 7,
		"month": time.Hour * 24 * 30,
	}
)

func main() {
	flag.Parse()
	if *version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}
	if *silent {
		log.SetOutput(ioutil.Discard)
	}
	if !*showTimestamp {
		log.SetFlags(0)
	}
	switch {
	case len(*username) == 0:
		log.Fatalf("Missing required --username parameter")
	case len(*password) == 0:
		log.Fatalf("Missing required --password parameter")
	}

	stats["started"] = time.Now().Unix()
	addr = ":" + strconv.Itoa(*port)
	hostname, _ = os.Hostname()

	mux := http.NewServeMux()
	mux.HandleFunc("/stats/", statsHandler)
	mux.HandleFunc("/", printHandler)

	srv := &http.Server{
		Addr:         addr,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second, // Go 1.8 only
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*generateCert()},
			// Causes servers to use Go's default ciphersuite preferences,
			// which are tuned to avoid attacks. Does nothing on clients.
			PreferServerCipherSuites: true,
			// Only use curves which have assembly implementations
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519, // Go 1.8 only
			},
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8 only
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		},
		Handler: mux,
	}

	log.Printf("Starting server %s on %s", hostname, addr)
	log.Println("Listening...")
	// Empty paths can be passed in as function will use Server.TLSConfig
	log.Fatal(srv.ListenAndServeTLS("", ""))

}

func generateCert() *tls.Certificate {
	log.Print("Generating TLS certificate")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %s", err)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: hostname},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour), // 20 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
}

func authenticate(w http.ResponseWriter, req *http.Request) bool {
	authUsername, authPassword, _ := req.BasicAuth()
	if authUsername != *username || authPassword != *password {
		w.Header().Set("WWW-Authenticate", `Basic realm="posh"`)
		http.Error(w, "Unauthorized: Authorization Required", http.StatusUnauthorized)
		return false
	}
	return true
}

func updateStats() {
	for prefix, duration := range statsDurations {
		count := prefix + "Count"
		start := prefix + "Start"

		if time.Now().Sub(time.Unix(stats[start], 0)) <= duration {
			stats[count] += 1
		} else {
			stats[count] = 1
			stats[start] = time.Now().Unix()
		}
	}
	stats["total"] += 1
	stats["last"] = time.Now().Unix()
}

func printHandler(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		fmt.Fprintf(w, "posh "+AppVersion+"\n")
	case http.MethodPost:
		if !authenticate(w, req) {
			return
		}
		printJob(w, req)
	case http.MethodOptions:
		w.Header().Set("Allow", "OPTIONS, GET, POST")
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func check(err error, w http.ResponseWriter, req *http.Request, statusCode int, statusMsg string) bool {
	if err != nil {
		http.Error(w, statusMsg, statusCode)
		log.Printf("%s - %s %d - %s", req.RemoteAddr, req.Proto, statusCode, err.Error())
		return true
	}
	return false
}

func printJob(w http.ResponseWriter, req *http.Request) {
	device, err := os.OpenFile(req.URL.Path, os.O_WRONLY, 0660)
	if check(err, w, req, http.StatusBadRequest, "Failed to open device at "+req.URL.Path) {
		return
	}
	defer device.Close()

	body, err := ioutil.ReadAll(req.Body)
	if check(err, w, req, http.StatusInternalServerError, "Failed to read POST body") {
		return
	}

	n, err := device.Write(body)
	if check(err, w, req, http.StatusInternalServerError, "Failed to write to device") {
		return
	}
	device.Sync()
	fmt.Fprintf(w, "%d", n)
	updateStats()
	log.Printf("%s - %s %d - Wrote %d bytes to %s", req.RemoteAddr, req.Proto,
		http.StatusOK, n, req.URL.Path)
}

func statsHandler(w http.ResponseWriter, req *http.Request) {
	if !authenticate(w, req) {
		return
	}
	fmt.Fprintf(w, "posh\n~~~~\n")
	fmt.Fprintf(w, "Started: %s\n", time.Unix(stats["started"], 0))
	if stats["total"] > 0 {
		fmt.Fprintf(w, "Last print job: %s\n", time.Unix(stats["last"], 0))
	}
	fmt.Fprintf(w, "Submitted print jobs, in the last:\n")
	fmt.Fprintf(w, " * Day: %d\n", stats["dayCount"])
	fmt.Fprintf(w, " * Week: %d\n", stats["weekCount"])
	fmt.Fprintf(w, " * Month: %d\n", stats["monthCount"])
	fmt.Fprintf(w, " * Total (since started): %d\n", stats["total"])
}
