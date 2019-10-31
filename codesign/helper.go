package codesign

import (
	"crypto/x509"
	"encoding/asn1"
	"howett.net/plist"
)

var(
  X509CertificateCommonNameOID = asn1.ObjectIdentifier{2, 5, 4, 3}
  X509CertificateOrganizationalUnitOID = asn1.ObjectIdentifier{2, 5, 4, 11}
  X509CertificateUserOID =  asn1.ObjectIdentifier{0,9,2342,19200300,100,1,1}
  PListOID = asn1.ObjectIdentifier{1,2,840,113549,1,7,1}
)

var(
	APPLE_ADS_OID =  []byte   { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64 }
	APPLE_EXTENSION_OID = []byte  { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x06 }
	APPLE_IOS_OID = []byte   { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x06, 0x02, 0x01 }
)

const(
	SHA1Length = 20
	SHA256Length = 32
	SHA256TruncatedLength = 20

	HashTypeSHA1 = 0x01            // CS_HASHTYPE_SHA1
	HashTypeSHA256 = 0x02          // CS_HASHTYPE_SHA256
	HashTypeSHA256Truncated = 0x03 // CS_HASHTYPE_SHA256_TRUNCATED - SHA256 truncated to 20 bytes
)

func GetHashLength(hashType byte)byte{
	switch hashType {
	case HashTypeSHA1:
		return SHA1Length
	case HashTypeSHA256:
		return SHA256Length
	case HashTypeSHA256Truncated:
		return SHA256TruncatedLength
	}
	return 0
}

func GetCertificateValue( certificate *x509.Certificate,  id asn1.ObjectIdentifier) string {
	name := certificate.Subject
	for _, n := range name.Names {
		if n.Type.Equal(id) {
			return n.Value.(string)
		}
	}
	return ""
}

func CreateRequirements(ident, certificateCN string)*Requirements {
	codeRequirements := new(Requirements)
	codeRequirement := &Requirement{
		Kind : RequirementKind,
	}
	codeRequirements.Add(DesignatedRequirementType, codeRequirement)

	identValue := &IdentValue{
		Value: []byte(ident),
	}
	appleGenericAnchor := new(AppleGenericAnchor)
	certificateField := new(CertificateField)
	certificateField.CertificateIndex = 0
	certificateField.FieldName = []byte("subject.CN")
	certificateField.Match.MatchOperation = MatchEqual
	certificateField.Match.MatchValue = []byte(certificateCN)

	certificateGeneric := new(CertificateGeneric)
	certificateGeneric.CertificateIndex = 1
	certificateGeneric.Oid = APPLE_IOS_OID
	certificateGeneric.Match.MatchOperation = MatchExists

	codeRequirement.Expression = &ExpressionAnd{
		Exp1: identValue,
		Exp2: &ExpressionAnd{
			Exp1: appleGenericAnchor,
			Exp2: &ExpressionAnd{
				Exp1: certificateField,
				Exp2: certificateGeneric,
			},
		},
	}

	return codeRequirements
}

func CreateEntitlements(entitlements EntitlementsFile)*Entitlements {
	entitlementsBlob := NewEntitlements()
	// XCode will remove the keychain-access-groups key from embedded entitlements
	// More info: https://github.com/openbakery/gradle-xcodePlugin/issues/220
	delete(entitlements, "keychain-access-groups")
	data, _ := plist.MarshalIndent(entitlements, plist.XMLFormat, "	")
	strData := string(data)
	strLen := len(strData)
	if strLen ==0{
		return nil
	}
	entitlementsBlob.Data = data
	return entitlementsBlob
}