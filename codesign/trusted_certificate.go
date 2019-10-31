package codesign

import "encoding/binary"


type TrustedCertificates struct {
}

func(v *TrustedCertificates)Length() int{
	return 4
}

func(v *TrustedCertificates)Load(buffer []byte)int {
	if binary.BigEndian.Uint32(buffer) != ExprTrustedCertificates{
		return 0
	}
	return v.Length()
}

func(v *TrustedCertificates)WriteBytes(buffer []byte)int{
	binary.BigEndian.PutUint32(buffer, ExprTrustedCertificates)
	return v.Length()
}


type TrustedCertificate struct {
	CertificateIndex uint32
}

func(v *TrustedCertificate)Length() int {
	return 8
}

func(v *TrustedCertificate)Load(buffer []byte)int {
	if binary.BigEndian.Uint32(buffer) != ExprTrustedCertificate{
		return 0
	}
	v.CertificateIndex =  binary.BigEndian.Uint32(buffer[4:])
	return 8
}

func(v *TrustedCertificate)WriteBytes(buffer []byte)int {
	binary.BigEndian.PutUint32(buffer, ExprTrustedCertificate)
	binary.BigEndian.PutUint32(buffer[4:], v.CertificateIndex)
	return 8
}