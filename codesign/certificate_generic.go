package codesign

import "encoding/binary"

type CertificateGeneric struct {
	CertificateIndex uint32
	Oid              []byte
	Match            MatchSuffix
}

func(v *CertificateGeneric)Length() int {
	return 8 + ExprDataLen(len(v.Oid)) + v.Match.Length()
}

func(v *CertificateGeneric)Load(buffer []byte)int {
	if binary.BigEndian.Uint32(buffer) != ExprCertificateGeneric{
		return 0
	}
	v.CertificateIndex =  binary.BigEndian.Uint32(buffer[4:])
	key, n1 := ExprReadData(buffer[8:])
	v.Oid = key
	n2 := v.Match.Load(buffer[8+n1:])
	return 8 + n1 + n2
}

func(v *CertificateGeneric)WriteBytes(buffer []byte)int {
	binary.BigEndian.PutUint32(buffer, ExprCertificateGeneric)
	binary.BigEndian.PutUint32(buffer[4:], v.CertificateIndex)
	n1 := ExprWriteData(buffer[8:], v.Oid)
	n2 := v.Match.WriteBytes(buffer[8+n1:])
	return 8 + n1 + n2
}

func(v *CertificateGeneric)GetBytes()[]byte{
	buffer:= make([]byte, v.Length())
	v.WriteBytes(buffer)
	return buffer
}