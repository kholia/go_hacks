package main

// https://go.dev/blog/tls-cipher-suites
// https://github.com/denji/golang-tls
// https://github.com/golang/go/blob/master/src/crypto/tls/cipher_suites.go

// https://www.ssllabs.com/ssltest/analyze.html?d=newtag.mywire.org&hideResults=on&ignoreMismatch=on&latest

// GOEXPERIMENT=boringcrypto go build server.go

import (
	"bufio"
	"crypto/tls"
	"log"
	"net"
)

func main() {
	log.SetFlags(log.Lshortfile)

	cer, err := tls.LoadX509KeyPair("newtag.mywire.org.crt", "newtag.mywire.org.key")
	if err != nil {
		log.Println(err)
		return
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer},
		CipherSuites: []uint16{
			/*
				// proxy.yaml.tmpl
				ECDHE-ECDSA-AES256-GCM-SHA384
				ECDHE-RSA-AES256-GCM-SHA384
				ECDHE-ECDSA-CHACHA20-POLY1305
				ECDHE-RSA-CHACHA20-POLY1305
				ECDHE-ECDSA-AES128-GCM-SHA256
				ECDHE-RSA-AES128-GCM-SHA256
				ECDHE-ECDSA-AES128-SHA256
				ECDHE-RSA-AES128-SHA256
			*/

			// AES128-GCM-SHA256:AES256-GCM-SHA384
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,

			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, // No FS
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,

			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // No FS

			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,

			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
	}

	ln, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()

		if err != nil {
			log.Println(err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		msg, err := r.ReadString('\n')
		tlscon, _ := conn.(*tls.Conn)
		state := tlscon.ConnectionState()
		log.Println(state.CipherSuite)

		if err != nil {
			log.Println(err)
			return
		}

		println(msg)

		n, err := conn.Write([]byte("world\n"))
		if err != nil {
			log.Println(n, err)
			return
		}
	}
}
