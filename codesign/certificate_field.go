package codesign

import "encoding/binary"

type CertificateField struct {
	CertificateIndex uint32
	FieldName        []byte
	Match            MatchSuffix
}

func(v *CertificateField)Length() int {
	return 8 + ExprDataLen(len(v.FieldName)) + v.Match.Length()
}

func(v *CertificateField)Load(buffer []byte)int {
	if binary.BigEndian.Uint32(buffer) != ExprCertificateField{
		return 0
	}
	v.CertificateIndex =  binary.BigEndian.Uint32(buffer[4:])
	key, n1 := ExprReadData(buffer[8:])
	v.FieldName = key
	n2 := v.Match.Load(buffer[8+n1:])
	return 8 + n1 + n2
}

func(v *CertificateField)WriteBytes(buffer []byte)int {
	binary.BigEndian.PutUint32(buffer, ExprCertificateField)
	binary.BigEndian.PutUint32(buffer[4:], v.CertificateIndex)
	n1 := ExprWriteData(buffer[8:], v.FieldName)
	n2 := v.Match.WriteBytes(buffer[8+n1:])
	return 8 + n1 + n2
}

func(v *CertificateField)GetBytes()[]byte{
	buffer:= make([]byte, v.Length())
	v.WriteBytes(buffer)
	return buffer
}