package codesign

import (
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/gamebtc/appsign/mach"
)


const(
	CS_Valid = 0x00000001                    // CS_VALID
	CS_AdHoc = 0x00000002                    // CS_ADHOC
	CS_GetTaskAllow = 0x00000004             // CS_GET_TASK_ALLOW
	CS_Installer = 0x00000008                // CS_INSTALLER
	CS_Hard = 0x00000100                     // CS_HARD
	CS_Kill = 0x00000200                     // CS_KILL
	CS_CheckExpiration = 0x00000400          // CS_CHECK_EXPIRATION
	CS_Restrict = 0x00000800                 // CS_RESTRICT
	CS_Enforcement = 0x00001000              // CS_ENFORCEMENT
	CS_RequireLibraryValidation = 0x00002000 // CS_REQUIRE_LV
	CS_EntitlementsValidated = 0x00004000    // CS_ENTITLEMENTS_VALIDATED
)

type CodeSignatureBlob interface {
	WriteBytes(buffer []byte) int
	Length() int
}

func ComputeHash(hashType byte, data []byte)[]byte {
	switch hashType {
	case HashTypeSHA1:
		sha1Hash := sha1.Sum(data)
		return sha1Hash[:]
	//case HashTypeSHA256:
	//case HashTypeSHA256Truncated:
	default:
		sha256Hash := sha256.Sum256(data)
		return sha256Hash[:]
	}
}

func ComputeHashes(hashType byte , pageSize int , data []byte)[][]byte {
	var hashes [][]byte
	for i := 0; i < len(data); i += pageSize {
		remaining := len(data) - i
		length := pageSize
		if remaining < pageSize {
			length = remaining
		}
		switch hashType {
		case HashTypeSHA1:
			sha1Hash := sha1.Sum(data[i : i+length])
			hashes = append(hashes, sha1Hash[:])
		case HashTypeSHA256:
			sha256Hash := sha256.Sum256(data[i : i+length])
			hashes = append(hashes, sha256Hash[:])
		case HashTypeSHA256Truncated:
			sha256Hash := sha256.Sum256(data[i : i+length])
			hashes = append(hashes, sha256Hash[:SHA256TruncatedLength])
		}
	}
	return hashes
}

const SpecialHashCount = 5
const ApplicationSpecificHashOffset = 4
const EntitlementsHashOffset = 5
func UpdateSpecialHashes(codeDirectory *CodeDirectory,
	codeToHash, infoFileBytes []byte ,
	codeRequirements *Requirements,
	codeResBytes []byte,
	entitlements *Entitlements) {

	ht := codeDirectory.HashType
	codeDirectory.CodeHashes = ComputeHashes(ht, codeDirectory.GetPageSize(), codeToHash)
	hashes := make([][]byte, 0, SpecialHashCount)
	hashes = append(hashes, ComputeHash(ht, infoFileBytes))
	hashes = append(hashes, ComputeHash(ht, codeRequirements.GetBytes()))
	hashes = append(hashes, ComputeHash(ht, codeResBytes))
	if SpecialHashCount >= ApplicationSpecificHashOffset {
		hashes = append(hashes, make([]byte, GetHashLength(ht)))
		if SpecialHashCount >= EntitlementsHashOffset {
			hashes = append(hashes, ComputeHash(ht, entitlements.GetBytes()))
		}
	}
	size := len(hashes)
	for i := 0; i < size/2; i++ {
		hashes[i], hashes[size-1-i] = hashes[size-1-i], hashes[i]
	}
	codeDirectory.SpecialHashes = hashes
}

func ResignExecutable(file *mach.MachObjectFile, bundleId string, certChain []*x509.Certificate,
	privateKey crypto.Signer, infoFileBytes, codeResBytes []byte, entitlements map[string]interface{} ) error {

	signCert := certChain[len(certChain)-1]
	certificateCN := GetCertificateValue(signCert, X509CertificateCommonNameOID)
	teamID := GetCertificateValue(signCert, X509CertificateOrganizationalUnitOID)

	linkEditSegment := mach.FindLinkEditSegment(file.LoadCommands)
	if linkEditSegment == nil {
		return errors.New("LinkEdit segment was not found")
	}
	cmd := file.LoadCommands[len(file.LoadCommands)-1]
	if cmd.Type() != mach.LC_CodeSignature {
		return errors.New("the last LoadCommand entry is not CodeSignature")
	}
	command := cmd.(*mach.CodeSignatureCommand)

	codeLength := command.DataOffset

	codeDirectory := CreateCodeDirectory(codeLength, bundleId, teamID, HashTypeSHA1)

	codeRequirements := CreateRequirements(bundleId, certificateCN)
	entitlementsBlob := CreateEntitlements(entitlements)
	codeBytes1 := codeDirectory.GetBytes()
	cmsSignature := new(CmsSignatureBlob)
	cmsSignature.Data = CmsGenerateSignature(certChain, privateKey, codeBytes1)

	codeSignature := new(CodeSignatureSuperBlob)
	codeSignature.Add(CSSLOT_CODEDIRECTORY, codeDirectory)
	codeSignature.Add(CSSLOT_REQUIREMENTS, codeRequirements)
	codeSignature.Add(CSSLOT_ENTITLEMENTS, entitlementsBlob)
	codeSignature.Add(CSSLOT_SIGNATURESLOT, cmsSignature)
	command.DataSize = uint32(codeSignature.Length())

	finalFileSize := command.DataOffset + command.DataSize
	mach.SegmentSetEndOffset(linkEditSegment, finalFileSize)

	codeToHash := file.GetBytes()[0:codeLength]
	UpdateSpecialHashes(codeDirectory, codeToHash, infoFileBytes, codeRequirements, codeResBytes, entitlementsBlob)

	codeBytes2 := codeDirectory.GetBytes()
	cmsSignature.Data = CmsGenerateSignature(certChain, privateKey, codeBytes2)
	codeSignatureBytes := codeSignature.GetBytes()

	newSize := int(codeLength) - file.DataOffset + int(command.DataSize)
	file.Data = file.Data[:newSize]
	offset := int(command.DataOffset) - file.DataOffset
	copy(file.Data[offset:], codeSignatureBytes)
	return nil
}