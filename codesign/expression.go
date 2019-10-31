package codesign

import (
	"encoding/binary"
)

// https://opensource.apple.com/source/libsecurity_codesigning/libsecurity_codesigning-55037.15/lib/requirement.h.auto.html
const(
	ExprFalse             = 0
	ExprTrue              = 1
	ExprIdent             = 2 // Parse canonical code [string]
	ExprAppleAnchor       = 3  // Signed by Apple as Apple's product
	ExprAnchorHash        = 4 // Parse anchor [cert hash]
	ExprInfoKeyValue      = 5 // Legacy [key; value]
	ExprAnd               = 6 // Binary prefix expr AND expr [expr; expr]
	ExprOr                = 7 // Binary prefix expr OR expr [expr; expr]
	ExprCodeDirectoryHash = 8
	ExprNot               = 9
	ExprInfoKeyField      = 10   // Info.plist key field [string; match suffix]
	ExprCertificateField = 11    // Certificate field [cert index; field name; match suffix]
	ExprTrustedCertificate = 12  // Require trust settings to approve one particular cert [cert index]
	ExprTrustedCertificates = 13 // Require trust settings to approve the cert chain.
	ExprCertificateGeneric = 14  // Certificate component by OID [cert index; oid; match suffix]
	ExprAppleGenericAnchor = 15  // Signed by Apple in any capacity
	ExprEntitlementField = 16    // Entitlement dictionary field [string; match suffix]
	ExprCertPolicy = 17			 // Certificate policy by OID [cert index; oid; match suffix]
	ExprNamedAnchor = 18		 // named anchor type
	ExprNamedCode = 19			 // named subroutine
	ExprCount = 20				 // (total opcode count in use)
)

type EntitlementsFile  =  map[string]interface{}

type RequirementExpression interface {
	Load(buffer []byte)int
	WriteBytes(buffer []byte)int
	Length()int
}

func ExprReadData(buffer []byte)([]byte, int) {
	length := int(binary.BigEndian.Uint32(buffer))
	data := buffer[4 : 4+length]
	return data, ExprDataLen(length)
}

func ExprDataLen(n int)int {
	padding := (4 - (n % 4)) % 4
	return 4 + n + padding
}

func ExprWriteData(desc []byte, src []byte) int {
	srcLen := len(src)
	binary.BigEndian.PutUint32(desc, uint32(srcLen))
	copy(desc[4:], src)
	padding := (4 - (srcLen % 4)) % 4
	if padding > 0 {
		copy(desc[4+srcLen:], make([]byte, padding))
	}
	return 4 + srcLen + padding
}

func ReadAnsiString(buffer []byte)(string, int) {
	data, length := ExprReadData(buffer)
	return string(data), length
}

func ReadExpression(buffer []byte)(RequirementExpression, int) {
	opName := binary.BigEndian.Uint32(buffer)
	var v RequirementExpression
	switch opName {
	case ExprFalse:
		v = new(BooleanFalse)
	case ExprTrue:
		v = new(BooleanTrue)
	case ExprIdent:
		v = new(IdentValue)
	case ExprAppleAnchor:
		v = new(AppleAnchor)
	case ExprAnchorHash:
		v = new(AnchorHash)
	case ExprInfoKeyValue:
		v = new(InfoKeyValue)
	case ExprAnd:
		v = new(ExpressionAnd)
	case ExprOr:
		v = new(ExpressionOr)
	case ExprCodeDirectoryHash:
		v = new(CodeDirectoryHash)
	case ExprNot:
		v = new(ExpressionNot)
	case ExprInfoKeyField:
		v = new(InfoKeyField)
	case ExprCertificateField:
		v = new(CertificateField)
	case ExprTrustedCertificate:
		v = new(TrustedCertificate)
	case ExprTrustedCertificates:
		v = new(TrustedCertificates)
	case ExprCertificateGeneric:
		v = new(CertificateGeneric)
	case ExprAppleGenericAnchor:
		v = new(AppleGenericAnchor)
	}
	if v == nil {
		return nil, 0
	}
	n := v.Load(buffer)
	return v, n
}
