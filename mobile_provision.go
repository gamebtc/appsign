package appsign

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io/ioutil"
	"strings"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"howett.net/plist"

	"github.com/gamebtc/appsign/codesign"
)

const PListHead = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">`
const PListTail =`</plist>`

var PListOIDByte []byte
func init() {
	PListOIDByte, _ = asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})
}

type MobileProvisionFile struct {
	AppIDName                   string
	ApplicationIdentifierPrefix []string
	CreationDate                time.Time
	Platform                    []string
	IsXcodeManaged              bool
	DeveloperCertificates       [][]byte
	ExpirationDate              time.Time
	Name                        string
	ProvisionedDevices          []string
	TeamIdentifier              []string
	TeamName                    string
	UUID                        string
	Entitlements                codesign.EntitlementsFile
	TimeToLive                  int
	Version                     int
	raw                         []byte `plist:"-"`
}

// 利用特殊标签查找字符串，性能更好
func readXmlPlistData(bin []byte)([]byte,error) {
	strBin := string(bin)
	headIndex := strings.Index(strBin, PListHead)
	tailIndex := strings.LastIndex(strBin, PListTail)
	if headIndex <= 0 || tailIndex <= 0 || tailIndex <= headIndex+len(PListHead) {
		return nil, errors.New("invalid plist file")
	}
	return bin[headIndex : tailIndex+len(PListTail)], nil
}

// 完整的解析ASN.1文件，更严谨
func readXmlPlistData2(bin []byte)([]byte,error) {
	pack, err := ber.ReadPacket(bytes.NewBuffer(bin))
	if err != nil {
		return nil, err
	}
	return []byte(FindPListXml(pack)), nil
}

func ParseMobileProvision(data []byte)(*MobileProvisionFile, error) {
	plistData, err := readXmlPlistData2(data)
	if err != nil {
		return nil, err
	}
	m := &MobileProvisionFile{}
	_, err = plist.Unmarshal(plistData, m)
	if err != nil {
		return nil, err
	}
	m.raw = data
	return m, nil
}

func ParseMobileProvisionFromFile(fileName string)(*MobileProvisionFile, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return ParseMobileProvision(data)
}

func (m *MobileProvisionFile)MatchingCertificate(certificate *x509.Certificate)bool {
	match := false
	for i := 0; i < len(m.DeveloperCertificates); i++ {
		certs, err := x509.ParseCertificates(m.DeveloperCertificates[i])
		if err != nil {
			return false
		}
		for _, cer := range certs {
			if certificate.Equal(cer) {
				match = true
				break
			}
		}
	}
	return match
}

func(m* MobileProvisionFile)BundleIdentifier()string {
	teamID, ok1 := m.Entitlements["com.apple.developer.team-identifier"]
	applicationID, ok2 := m.Entitlements["application-identifier"]
	if ok1 && ok2 {
		teamID := teamID.(string)
		applicationID := applicationID.(string)
		if strings.Index(applicationID, teamID) == 0 && len(applicationID) > len(teamID) {
			return applicationID[len(teamID)+1:]
		}
	}
	return ""
}

func EqualOid(a []byte, b[]byte) bool{
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func FindPListOID(packet *ber.Packet) *ber.Packet {
	size := len(packet.Children)
	if size == 2 {
		if EqualOid(PListOIDByte, packet.Children[0].Bytes()) {
			return packet.Children[1]
		}
	}
	for i := 0; i < size; i++ {
		p := FindPListOID(packet.Children[i])
		if p != nil {
			return p
		}
	}
	return nil
}

func FindPListXml(packet *ber.Packet) string{
	if oid := FindPListOID(packet);oid!=nil{
		if oid.Children[0].Tag == ber.TagOctetString{
			return oid.Children[0].Value.(string)
		}
	}
	return ""
}