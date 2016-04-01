// Check OCSP revocation status.
// 1. Get stapled response from tls conn.OCSPResponse()
//      and check using ocsp.ParseResponse()
// 2. If there is no stapled response, check manually:
//      a. Get issuer and server x509 certs
//      b. Get OCSP url from the server's x509 Certificate.OCSPServer
//      c. Use ocsp.CreateRequest() to create a request
//      d. url-base64 encode the request and make a GET request to
//          https://{url}/{encoded-request}
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/ocsp"
)

var (
	destURL = flag.String("url", "", "url to check")
)

func grabIssuerCert(connState *tls.ConnectionState) *x509.Certificate {
	return connState.VerifiedChains[0][1]
}

func grabServerCert(connState *tls.ConnectionState) *x509.Certificate {
	return connState.VerifiedChains[0][0]
}

func manualCheck(connState *tls.ConnectionState) {
	server := grabServerCert(connState)
	issuer := grabIssuerCert(connState)
	ocspURL := server.OCSPServer[0]
	log.Printf("Server: %v\n", server.Subject.CommonName)
	log.Printf("Issuer: %v\n", issuer.Subject.CommonName)
	log.Printf("OCSP URL: %v\n", ocspURL)

	ocspReq, err := ocsp.CreateRequest(server, issuer, nil)
	if err != nil {
		log.Fatalln("error creating ocsp request: ", err)
	}
	body := bytes.NewReader(ocspReq)
	req, err := http.NewRequest("POST", ocspURL, body)
	if err != nil {
		log.Fatalln("error creating http post request: ", err)
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln("error sending post request: ", err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	io.Copy(buf, resp.Body)
	parseResponse(buf.Bytes(), issuer)
}

func parseResponse(response []byte, issuer *x509.Certificate) {
	resp, err := ocsp.ParseResponse(response, issuer)
	if err != nil {
		log.Fatalln("error parsing response: ", err)
	}
	if resp.Status == ocsp.Good {
		log.Println("Certificate Status Good.")
	} else if resp.Status == ocsp.Unknown {
		log.Println("Certificate Status Unknown")
	} else {
		log.Println("Certificate Status Revoked")
	}
}

func stapledCheck(connState *tls.ConnectionState) {
	server := grabServerCert(connState)
	issuer := grabIssuerCert(connState)
	log.Printf("Server: %v\n", server.Subject.CommonName)
	log.Printf("Issuer: %v\n", issuer.Subject.CommonName)

	parseResponse(connState.OCSPResponse, issuer)
}

func main() {
	flag.Parse()

	if *destURL == "" {
		log.Fatalln("must provide a url")
	}
	if !strings.HasPrefix(*destURL, "https") {
		log.Fatalln("must provide a https url")
	}

	resp, err := http.Get(*destURL)
	if err != nil {
		log.Fatalln(err)
	}
	cs := resp.TLS
	if cs == nil {
		log.Fatalln("no connection state")
	}

	if cs.OCSPResponse == nil {
		// manually check revocation
		log.Println("manual check")
		manualCheck(cs)
	} else {
		// parse the ocsp response
		log.Println("stapled check")
		stapledCheck(cs)
	}
}
