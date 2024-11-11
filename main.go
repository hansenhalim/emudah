package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"time"
)

type CertificateRequest struct {
	CertName    string      `json:"cert_name"`
	Passphrase  string      `json:"passphrase"`
	CertProfile string      `json:"cert_profile"`
	UserProfile UserProfile `json:"user_profile"`
}

type UserProfile struct {
	CommonName   string `json:"common_name"`
	Country      string `json:"country"`
	Organization string `json:"organization"`
	Email        string `json:"email"`
}

type CertificateChain struct {
	CertSerialNumber string `json:"cert_serial_number"`
	Certificate      string `json:"certificate"`
	ValidityStart    string `json:"validity_start"`
	ValidityEnd      string `json:"validity_end"`
}

type CertificateResponse struct {
	StatusCode    string `json:"status_code"`
	StatusMessage string `json:"status_message"`
	Data          struct {
		CertChain []CertificateChain `json:"cert_chain"`
	} `json:"data"`
}

func main() {
	http.HandleFunc("/emRA-eSign/keygen/csr", handleCSR)
	log.Println("Server is running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleCSR(w http.ResponseWriter, r *http.Request) {
	// Parse JSON request body
	var certReq CertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&certReq); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Generate certificates
	certChain, err := generateCertificates(certReq)
	if err != nil {
		http.Error(w, "Failed to generate certificate", http.StatusInternalServerError)
		return
	}

	// Prepare response
	response := CertificateResponse{
		StatusCode:    "success",
		StatusMessage: "Certificate is created successfully",
	}
	response.Data.CertChain = certChain

	// Send response as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func generateCertificates(certReq CertificateRequest) ([]CertificateChain, error) {
	// Create private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Generate certificate chain
	certChain := []CertificateChain{}
	for i := 0; i < 3; i++ {
		// Create a new serial number
		serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, err
		}

		// Create certificate template
		certTemplate := &x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName:   certReq.UserProfile.CommonName,
				Country:      []string{certReq.UserProfile.Country},
				Organization: []string{certReq.UserProfile.Organization},
			},
			EmailAddresses: []string{
				certReq.UserProfile.Email,
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(10, 0, 0), // Valid for 10 years
			KeyUsage:  x509.KeyUsageDigitalSignature,
		}

		// Generate a certificate
		certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &priv.PublicKey, priv)
		if err != nil {
			return nil, err
		}

		// Encode certificate to PEM format
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

		// Add to certificate chain
		certChain = append(certChain, CertificateChain{
			CertSerialNumber: serialNumber.Text(16),
			Certificate:      string(certPEM),
			ValidityStart:    certTemplate.NotBefore.Format(time.RFC3339),
			ValidityEnd:      certTemplate.NotAfter.Format(time.RFC3339),
		})
	}

	return certChain, nil
}
