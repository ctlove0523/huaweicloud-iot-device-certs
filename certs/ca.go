package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"
)

func LoadPrivateKey(keyFile string) (*rsa.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		fmt.Println("read key file content failed")
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)

	fmt.Println(block.Type)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("parse private key failed")
		return nil, err
	}
	fmt.Println("load key from file success")
	return key, nil
}

func LoadCertRequest(requestFile string) (*x509.CertificateRequest, error) {
	// load client certificate request
	csrBytes, err := ioutil.ReadFile(requestFile)
	if err != nil {
		fmt.Printf("read request file %s failed\n", requestFile)
		return nil, err
	}
	block, _ := pem.Decode(csrBytes)
	if block == nil {
		panic("pem.Decode failed")
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		fmt.Printf("parse certificate request from %s failed,error %s\n", requestFile, err)
		return nil, err
	}

	return req, nil
}

func CertificateRequestToCertificate(request *x509.CertificateRequest) (*x509.Certificate, error) {
	template := &x509.Certificate{
		Signature:          request.Signature,
		SignatureAlgorithm: request.SignatureAlgorithm,

		PublicKeyAlgorithm: request.PublicKeyAlgorithm,
		PublicKey:          request.PublicKey,

		SerialNumber: big.NewInt(2),
		Issuer:       request.Subject,
		Subject:      request.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	return template, nil
}
func LoadCert(certFile string) (*x509.Certificate, error) {
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		fmt.Printf("read cert file %s content failed\n", certFile)
		return nil, err
	}

	block, _ := pem.Decode(certBytes)
	fmt.Println(block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("parse cert file %s failed\n", certFile)
		fmt.Println(err)
		return nil, err
	}
	fmt.Println("load cert from file success")
	return cert, nil
}
func CreateRsaPrivetKey(bits int) ([]byte, error) {
	bitSize := bits
	if bitSize < 2048 {
		bitSize = 2048
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		fmt.Println("generate ras key failed")
		return nil, err
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	fmt.Println("generate ras key success")

	return privateKeyBytes, nil

}

func CreateSerialNumber() (n *big.Int, err error) {
	max := new(big.Int).Lsh(big.NewInt(1), 256)
	serialNumber, err := rand.Int(rand.Reader, max)
	return serialNumber, err
}

func CreateCaWithKey(key *rsa.PrivateKey) ([]byte, error) {
	subject := pkix.Name{
		Country:            []string{"China"},
		Province:           []string{"guangdong"},
		Locality:           []string{"shenzhen"},
		Organization:       []string{"huawei"},
		OrganizationalUnit: []string{"iot"},
		CommonName:         "iotda",
	}

	serialNumber, _ := CreateSerialNumber()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true,
	}

	caCert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		fmt.Println("create ca cert failed")
		panic(err)
	}

	return caCert, err
}

func CreateCa(privateKey []byte) ([]byte, error) {
	subject := pkix.Name{
		Country:            []string{"China"},
		Province:           []string{"guangdong"},
		Locality:           []string{"shenzhen"},
		Organization:       []string{"huawei"},
		OrganizationalUnit: []string{"iot"},
		CommonName:         "iotda",
	}

	serialNumber, _ := CreateSerialNumber()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true,
	}

	key, err := x509.ParsePKCS1PrivateKey(privateKey)
	if err != nil {
		fmt.Println("parse private key failed")
		panic(err)
	}
	caCert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		fmt.Println("create ca cert failed")
		panic(err)
	}

	return caCert, err
}

func CreateCsr(privateKey *rsa.PrivateKey, commonName string) ([]byte, error) {
	subject := pkix.Name{
		Country:            []string{"China"},
		Province:           []string{"guangdong"},
		Locality:           []string{"shenzhen"},
		Organization:       []string{"huawei"},
		OrganizationalUnit: []string{"iot"},
		CommonName:         commonName,
	}

	request := &x509.CertificateRequest{
		Subject: subject,
	}

	return x509.CreateCertificateRequest(rand.Reader, request, privateKey)

}

func CreateVerificationCaCert(key *rsa.PrivateKey, ca []byte, code string) ([]byte, error) {

	subject := pkix.Name{
		Country:            []string{"China"},
		Province:           []string{"guangdong"},
		Locality:           []string{"shenzhen"},
		Organization:       []string{"huawei"},
		OrganizationalUnit: []string{"iot"},
		CommonName:         code,
	}
	serialNumber, _ := CreateSerialNumber()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true,
	}

	caCert, err := x509.ParseCertificate(ca)
	if err != nil {
		panic(err)
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, caCert, key.PublicKey, key)

	return cert, err
}

func test() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Errorf("create private key failed %s", err)
		panic(err)
	}
	content := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: content,
	}

	file, err := os.Create("privateKey.key")
	if err != nil {
		panic(err)
	}

	err = pem.Encode(file, block)
	if err != nil {
		panic(err)

	}

	subject := pkix.Name{
		Country:            []string{"China"},
		Province:           []string{"guangdong"},
		Locality:           []string{"shenzhen"},
		Organization:       []string{"huawei"},
		OrganizationalUnit: []string{"iot"},
		CommonName:         "iotda",
	}

	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, max)
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true,
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)

	block = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}

	file, err = os.Create("ca.pem")
	if err != nil {
		panic(err)
	}

	err = pem.Encode(file, block)
	if err != nil {
		panic(err)

	}

}
