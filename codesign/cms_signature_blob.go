package codesign

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"

	"go.mozilla.org/pkcs7"

	"github.com/mastahyeti/cms"
	"github.com/mastahyeti/cms/oid"
	"github.com/mastahyeti/cms/protocol"
)

const CmsSignatureBlobSign = 0xfade0b01 // CSMAGIC_BLOBWRAPPER
type CmsSignatureBlob struct {
	// uint Magic;
	// uint Length;
   Data []byte
}

func(v *CmsSignatureBlob)Length() int {
	return 8 + len(v.Data)
}

func(v *CmsSignatureBlob)Load(buffer []byte)int {
	length := int(binary.BigEndian.Uint32(buffer[4:]))
	data := make([]byte, length-8)
	copy(data, buffer[8:])
	v.Data = data
	return length
}

func(v *CmsSignatureBlob)WriteBytes(buffer []byte)int {
	length := v.Length()
	binary.BigEndian.PutUint32(buffer, CmsSignatureBlobSign)
	binary.BigEndian.PutUint32(buffer[4:], uint32(length))
	copy(buffer[8:], v.Data)
	return length
}

func(v *CmsSignatureBlob)GetBytes() []byte {
	buffer := make([]byte, v.Length())
	v.WriteBytes(buffer)
	return buffer
}

func CmsGenerateSignature(certChain []*x509.Certificate, privateKey crypto.Signer, messageToSign []byte) []byte {
	size := len(certChain)
	signingCertificate := certChain[size-1]
	cmsChain := make([]*x509.Certificate, size)
	copy(cmsChain, certChain)
	for i := 0; i < (size-1)/2; i++ {
		j := size - 2 - i
		cmsChain[i], cmsChain[j] = cmsChain[j], cmsChain[i]
	}
	//certChain = cmsChain
	certificateStore := x509.NewCertPool()
	for _, cert := range cmsChain {
		certificateStore.AddCert(cert)
	}

	eci, _ := protocol.NewEncapsulatedContentInfo(oid.ContentTypeData, messageToSign)
	sd, _ := protocol.NewSignedData(eci)


	sd.AddSignerInfo(cmsChain, privateKey)

	der, _ := sd.ContentInfoDER()
	der2, _ := cms.Sign(messageToSign, cmsChain, privateKey)

	der3, _ := cms.SignDetached(messageToSign, cmsChain, privateKey)

	der4, _:=SignAndDetach(messageToSign, signingCertificate, privateKey)

	if len(der2) > 1000000000 && len(der3) > 100000  && len(der4)>100000{
		return der2
	}
	return der
}

func SignAndDetach(content []byte, cert *x509.Certificate, privkey crypto.PrivateKey) (signed []byte, err error) {
	toBeSigned, err := pkcs7.NewSignedData(content)
	if err != nil {
		err = fmt.Errorf("Cannot initialize signed data: %s", err)
		return
	}
	if err = toBeSigned.AddSigner(cert, privkey, pkcs7.SignerInfoConfig{}); err != nil {
		err = fmt.Errorf("Cannot add signer: %s", err)
		return
	}

	// Detach signature, omit if you want an embedded signature
	toBeSigned.Detach()

	signed, err = toBeSigned.Finish()
	if err != nil {
		err = fmt.Errorf("Cannot finish signing data: %s", err)
		return
	}

	// Verify the signature
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})
	p7, err := pkcs7.Parse(signed)
	if err != nil {
		err = fmt.Errorf("Cannot parse our signed data: %s", err)
		return
	}

	// since the signature was detached, reattach the content here
	p7.Content = content

	if bytes.Compare(content, p7.Content) != 0 {
		err = fmt.Errorf("Our content was not in the parsed data:\n\tExpected: %s\n\tActual: %s", content, p7.Content)
		return
	}
	if err = p7.Verify(); err != nil {
		err = fmt.Errorf("Cannot verify our signed data: %s", err)
		return
	}

	return signed, nil
}