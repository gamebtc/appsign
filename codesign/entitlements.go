package codesign


const CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171 // CSMAGIC_EMBEDDED_ENTITLEMENTS
type Entitlements struct {
	CodeSignatureGenericBlob
}

func NewEntitlements()*Entitlements {
	return &Entitlements{
		CodeSignatureGenericBlob{
			Magic: CSMAGIC_EMBEDDED_ENTITLEMENTS,
		},
	}
}