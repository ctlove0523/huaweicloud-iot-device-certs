package api

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	iotda "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iotda/v5"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iotda/v5/model"
	region "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iotda/v5/region"
	"huaweicloud-iot-device-certs/certs"
	"io/ioutil"
	"os"
)

const ak = "KVE3VJHKYRIGOKXVDN50"
const sk = "NSCCGvCyEya7c7VL32YmrqZrERdo26y5WJjdSqw1"

var auth = basic.NewCredentialsBuilder().
	WithAk(ak).
	WithSk(sk).
	Build()

var client = iotda.NewIoTDAClient(iotda.IoTDAClientBuilder().
	WithCredential(auth).
	WithRegion(region.CN_NORTH_4).
	WithEndpoint("https://iotda.cn-north-4.myhuaweicloud.com").
	Build())

func CreateCaAndUpload() {
	key, err := certs.CreateRsaPrivetKey(4096)
	if err != nil {
		fmt.Printf("create ras privaet key failed,error = %s\n", err)
		return
	}

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: key,
	}

	file, err := os.Create("ca.key")
	if err != nil {
		panic(err)
	}

	err = pem.Encode(file, block)
	if err != nil {
		panic(err)
	}

	caCert, err := certs.CreateCa(key)

	block = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert,
	}

	caFile, err := os.Create("ca.pem")
	if err != nil {
		panic(err)
	}

	err = pem.Encode(caFile, block)
	if err != nil {
		panic(err)
	}

	caBytes, _ := ioutil.ReadFile("ca.pem")

	appId := "4825ce06e5d6430b80cc898e9102eff5"
	content := string(caBytes)

	req := &model.AddCertificateRequest{
		Body: &model.CreateCertificateDto{
			AppId:   &appId,
			Content: content,
		},
	}
	resp, err := client.AddCertificate(req)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(resp)
}

func getCertificateVerifyCode(certificatedId string) (*string, error) {
	request := &model.ListCertificatesRequest{

	}
	resp, err := client.ListCertificates(request)
	if err != nil {
		fmt.Printf("list certificate failed %s", err)
		return nil, err
	}

	verifyCode := ""
	for i := 0; i < len(*resp.Certificates); i++ {
		certificate := (*resp.Certificates)[i]
		if *certificate.CertificateId == certificatedId {
			verifyCode = *certificate.VerifyCode
			break
		}
	}

	return &verifyCode, nil
}

func VerifyCa(certId string) {
	verifyCode, err := getCertificateVerifyCode(certId)
	if err != nil {
		return
	}

	fmt.Println(*verifyCode)

	key, _ := certs.LoadPrivateKey("ca.key")
	csrBytes, err := certs.CreateCsr(key, *verifyCode)
	if err != nil {
		panic(err)
	}

	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}

	csrFile, err := os.Create("certId.csr")
	if err != nil {
		panic(err)
	}

	pem.Encode(csrFile, block)

	ca, _ := certs.LoadCert("ca.pem")

	cst, _ := certs.LoadCertRequest("certId.csr")

	template, err := certs.CertificateRequestToCertificate(cst)
	if err != nil {
		fmt.Printf("convert request to cert failed %s\n", err)
		panic(err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, ca, template.PublicKey, key)
	if err != nil {
		fmt.Printf("create cert failed %s\n", err)
		panic(err)
	}

	block = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}

	clientFile, err := os.Create("client.pem")
	if err != nil {
		panic(err)
	}

	pem.Encode(clientFile, block)


	clientFileBytes, _ := ioutil.ReadFile("client.pem")
	req := &model.CheckCertificateRequest{
		CertificateId: certId,
		ActionId:      "verify",
		Body: &model.VerifyCertificateDto{
			VerifyContent: string(clientFileBytes),
		},
	}
	resp, err := client.CheckCertificate(req)

	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(resp)

}

func Test() {
	// 创建认证
	request := &model.ListCertificatesRequest{

	}
	resp, err := client.ListCertificates(request)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(resp)
}
