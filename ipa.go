package appsign

import (
	"archive/zip"
	"crypto"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/pkcs12"

	"github.com/gamebtc/appsign/codesign"
	"github.com/gamebtc/appsign/mach"
)

const  CodeResourcesFilePath = "_CodeSignature/CodeResources"
const  MobileProvisionFileName = "embedded.mobileprovision"
const  InfoFileName = "Info.plist"
const  ZipDirectorySeparator = "/"

type ZipEntry struct {
	Name  string //文件名
	Data  []byte //解压后的数据
	IsDir bool   //是否是目录
}

var  invalIdFile =  errors.New("invalid directory structure for IPA file")

type IpaFile struct {
	srcFile          string
	entries          []*ZipEntry
	appDirectoryPath string
	mobileProvision  *MobileProvisionFile
	//infoFile         *InfoFile
	//exeName          string
}

func(f *IpaFile)Load(zipFile string) error {
	f.srcFile = zipFile
	reader, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	appDirectoryPath, err := GetAppDirectoryPath(reader.File)
	if err != nil {
		return err
	}
	embedded := appDirectoryPath + MobileProvisionFileName
	entries := make([]*ZipEntry, 0, len(reader.File))
	var mobileProvision *MobileProvisionFile
	for _, file := range reader.File {
		isDir := file.FileHeader.Mode().IsDir()
		var bin []byte
		if isDir == false {
			rc, err := file.Open()
			if err != nil {
				return err
			}
			bin, err = ioutil.ReadAll(rc)
			if err != nil {
				return invalIdFile
			}
			if file.Name == embedded {
				mobileProvision, err = ParseMobileProvision(bin)
				if err != nil {
					return invalIdFile
				}
			}
		}
		entries = append(entries, &ZipEntry{Name: file.Name, Data: bin, IsDir: isDir})
	}
	if mobileProvision == nil {
		return invalIdFile
	}
	f.entries = entries
	f.appDirectoryPath = appDirectoryPath
	f.mobileProvision = mobileProvision
	return nil
}

func GetAppDirectoryPath(files []*zip.File) (string,error) {
	var names []string
	for _, file := range files {
		if file.FileHeader.Mode().IsDir() {
			name := file.Name
			if len(name) > 8 && strings.LastIndex(name, "Payload"+ZipDirectorySeparator) == 0 {
				subPath := name[8:]
				subPath = strings.TrimRight(subPath, ZipDirectorySeparator)
				if !strings.Contains(subPath, ZipDirectorySeparator) {
					names = append(names, file.Name)
				}
			}
		}
	}
	if len(names) != 1 {
		return "", errors.New("invalid directory structure for IPA file")
	}
	return names[0], nil
}

func(f *IpaFile)GetFileBytes(name string)([]byte,error) {
	path := f.appDirectoryPath + name
	for i := 0; i < len(f.entries); i++ {
		if f.entries[i].Name == path {
			return f.entries[i].Data, nil
		}
	}
	return nil, errors.New("not find file")
}

func(f *IpaFile)GetMobileProvision()(*MobileProvisionFile, error) {
	data, err := f.GetFileBytes(MobileProvisionFileName)
	if err != nil {
		return nil, err
	}
	return ParseMobileProvision(data)
}

func(f *IpaFile)GetCodeResourcesFile()(*codesign.CodeResourcesFile, error) {
	data, err := f.GetFileBytes(CodeResourcesFilePath)
	if err != nil {
		return nil, err
	}
	return codesign.ParseCodeResources(data)
}

func(f *IpaFile)GetInfoFile()(*InfoFile, error) {
	data, err := f.GetFileBytes(InfoFileName)
	if err != nil {
		return nil, err
	}
	return ParseInfo(data)
}

func(f *IpaFile)GetBundleIdentifier()string {
	if infoFile, err := f.GetInfoFile(); err == nil {
		return infoFile.BundleId()
	}
	return ""
}

func(f *IpaFile) ReplaceFile(name string, data []byte) {
	path := f.appDirectoryPath + name
	for i := 0; i < len(f.entries); i++ {
		if f.entries[i].Name == path {
			f.entries[i].Data = data
			return
		}
	}
	f.entries = append(f.entries, &ZipEntry{Name: path, Data: data, IsDir: false})
}

func appleCertificateStore(path string) ([]*x509.Certificate, error) {
	bin, err := ioutil.ReadFile(path + "AppleIncRootCertificate.cer")
	if err != nil {
		return nil, err
	}
	appleIncRootCertificate, err := x509.ParseCertificates(bin)
	if err != nil {
		return nil, err
	}
	bin, err = ioutil.ReadFile(path + "AppleWWDRCA.cer")
	if err != nil {
		return nil, err
	}
	appleWWDRCA, err := x509.ParseCertificates(bin)
	if err != nil {
		return nil, err
	}
	certificateStore := append(appleIncRootCertificate, appleWWDRCA...)
	return certificateStore, nil
}

func ResignIpa(f *IpaFile, mobileProvisionBytes, signCertBytes []byte, certPwd, outFile string) error {
	privateKey, signCert, err := pkcs12.Decode(signCertBytes, certPwd)
	if err != nil {
		return err
	}
	var mobileProvision *MobileProvisionFile
	if len(mobileProvisionBytes) == 0 {
		mobileProvision = f.mobileProvision
	} else {
		mobileProvision, err = ParseMobileProvision(mobileProvisionBytes)
		if err != nil {
			return err
		}
	}

	if mobileProvision.MatchingCertificate(signCert) == false {
		return errors.New("the signing certificate given does not match any specified in the mobile provision file")
	}
	certificateStore, err := appleCertificateStore("")
	if len(certificateStore) == 0 || err != nil {
		return errors.New("failed to read certificate store")
	}
	certificateChain := append(certificateStore, signCert)
	return f.ResignIPA(certificateChain, mobileProvision, privateKey.(crypto.Signer), outFile)
}

func(f *IpaFile) ResignIPA(certChain []*x509.Certificate, mobileProvision *MobileProvisionFile, privateKey crypto.Signer, outFile string)error {
	infoFile, err := f.GetInfoFile()
	if err != nil {
		return err
	}

	exeName := infoFile.ExecutableName()
	buffer, err := f.GetFileBytes(exeName)
	if err != nil {
		return err
	}

	bundleId := mobileProvision.BundleIdentifier()
	infoFile.ReplaceBundleId(bundleId)

	infoFileBytes, err := infoFile.Marshal()
	if err != nil {
		return err
	}

	codeRes, err := f.GetCodeResourcesFile()
	if err != nil {
		return err
	}
	codeRes.UpdateFileHash(InfoFileName, infoFileBytes)
	codeRes.UpdateFileHash(MobileProvisionFileName, mobileProvision.raw)
	codeResBytes, err := codeRes.Marshal()
	if err != nil {
		return err
	}

	files := mach.ReadMachObjects(buffer)
	for _, file := range files {
		codesign.ResignExecutable(file, bundleId, certChain, privateKey, infoFileBytes, codeResBytes, mobileProvision.Entitlements)
	}
	execBytes := mach.PackMachObjects(files)
	return f.WriteNewFile(mobileProvision, infoFileBytes, codeResBytes, execBytes, infoFile.ExecutableName(), outFile)
}

func(f *IpaFile) WriteNewFile(mobileProvision *MobileProvisionFile, infoFileBytes, codeResBytes, execBytes []byte, execName, outFile string) error {
	d, _ := os.Create(outFile)
	defer d.Close()
	zw := zip.NewWriter(d)
	defer zw.Close()
	execPath := f.appDirectoryPath + execName
	embedded := f.appDirectoryPath + MobileProvisionFileName
	codeResPath := f.appDirectoryPath + CodeResourcesFilePath
	infoPath := f.appDirectoryPath + InfoFileName
	for _, file := range f.entries {
		writer, err := zw.Create(file.Name)
		if err != nil {
			return err
		}
		if file.IsDir == false {
			switch file.Name {
			case embedded:
				writer.Write(mobileProvision.raw)
			case codeResPath:
				writer.Write(codeResBytes)
			case infoPath:
				writer.Write(infoFileBytes)
			case execPath:
				writer.Write(execBytes)
			default:
				writer.Write(file.Data)
			}
		}
	}
	return nil
}
