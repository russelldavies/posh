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
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"time"
)

const (
	AppVersion        = "1.1.1"
	defaultConfigFile = "/etc/posh.json"
	defaultPort       = 443

	Day   = time.Hour * 24
	Week  = Day * 7
	Month = Week * 4
)

type Configuration struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Port     int    `json:"port,omitempty"`
}

type Stats struct {
	start      time.Time
	last       time.Time
	totalCount int64
	dayCount   int64
	dayStart   time.Time
	weekCount  int64
	weekStart  time.Time
	monthCount int64
	monthStart time.Time
}

var (
	config Configuration

	usernamePtr = flag.String("username", "", "Authentication username")
	passwordPtr = flag.String("password", "", "Authentication password")
	portPtr     = flag.Int("port", 0, "Port to listen on")

	configFilePtr    = flag.String("c", defaultConfigFile, "Configuration file")
	silentPtr        = flag.Bool("s", false, "Silent; do not output anything")
	showTimestampPtr = flag.Bool("t", false, "Show timestamp; include timestamp in log messages")
	versionPtr       = flag.Bool("version", false, "Print version")

	stats = Stats{start: time.Now()}
)

func main() {
	flag.Parse()
	if *versionPtr {
		fmt.Println(AppVersion)
		os.Exit(0)
	}
	if *silentPtr {
		log.SetOutput(ioutil.Discard)
	}
	if !*showTimestampPtr {
		log.SetFlags(0)
	}

	config = Configuration{Port: defaultPort}
	content, err := ioutil.ReadFile(*configFilePtr)
	if err != nil {
		log.Println("Configuration file " + *configFilePtr + " could not be read")
	} else {
		err = json.Unmarshal(content, &config)
		if err != nil {
			log.Fatal("Invalid configuration file")
		}
	}
	if *usernamePtr != "" {
		log.Printf("asdf")
		config.Username = *usernamePtr
	}
	if *passwordPtr != "" {
		config.Password = *passwordPtr
	}
	if *portPtr != 0 {
		config.Port = *portPtr
	}
	switch {
	case len(config.Username) == 0:
		log.Fatal("Username has not been set.")
	case len(config.Password) == 0:
		log.Fatal("Password has not been set.")
	}

	addr := ":" + strconv.Itoa(config.Port)
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

	log.Printf("Starting server on %s", addr)
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

	hostname, _ := os.Hostname()
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
	if authUsername != config.Username || authPassword != config.Password {
		w.Header().Set("WWW-Authenticate", `Basic realm="posh"`)
		http.Error(w, "Unauthorized: Authorization Required", http.StatusUnauthorized)
		return false
	}
	return true
}

func updateStats() {
	stats.totalCount += 1
	stats.last = time.Now()

	set := func(count *int64, start *time.Time, duration time.Duration) {
		if time.Since(*start) <= duration {
			*count += 1
		} else {
			*count = 1
			*start = time.Now()
		}
	}
	set(&stats.dayCount, &stats.dayStart, Day)
	set(&stats.weekCount, &stats.weekStart, Week)
	set(&stats.monthCount, &stats.monthStart, Month)
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
	fd, err := syscall.Open(req.URL.Path, os.O_WRONLY, 0666)
	if check(err, w, req, http.StatusBadRequest, "Failed to open device at "+req.URL.Path) {
		return
	}
	defer syscall.Close(fd)

	body, err := ioutil.ReadAll(req.Body)
	if check(err, w, req, http.StatusInternalServerError, "Failed to read POST body") {
		return
	}

	n, err := syscall.Write(fd, body)
	if check(err, w, req, http.StatusInternalServerError, "Failed to write to device") {
		return
	}
	fmt.Fprintf(w, "%d", n)
	updateStats()
	log.Printf("%s - %s %d - Wrote %d bytes to %s", req.RemoteAddr, req.Proto,
		http.StatusOK, n, req.URL.Path)
}

func statsHandler(w http.ResponseWriter, req *http.Request) {
	if !authenticate(w, req) {
		return
	}
	displayCount := func(count *int64, start *time.Time, duration time.Duration) int64 {
		if time.Since(*start) <= duration {
			return *count
		} else {
			return 0
		}
	}

	fmt.Fprintf(w, "posh %s\n~~~~~~~~~~\n", AppVersion)
	fmt.Fprintf(w, "Start time: %s\n", stats.start.Format(time.RFC3339))
	if stats.totalCount > 0 {
		fmt.Fprintf(w, "Last print job: %s\n", stats.last.Format(time.RFC3339))
	}
	fmt.Fprintf(w, "Submitted print jobs, in the last:\n")
	fmt.Fprintf(w, " * Day: %d\n", displayCount(&stats.dayCount, &stats.dayStart, Day))
	fmt.Fprintf(w, " * Week: %d\n", displayCount(&stats.weekCount, &stats.weekStart, Week))
	fmt.Fprintf(w, " * Month: %d\n", displayCount(&stats.monthCount, &stats.monthStart, Month))
	fmt.Fprintf(w, " * Total (since started): %d\n", stats.totalCount)
}
