package codesign

import (
	"crypto/sha1"
	"crypto/sha256"
	"io/ioutil"

	"howett.net/plist"
)

type CodeResourcesFile struct {
	dict map[string]interface{}
	format int
}

func (c *CodeResourcesFile)Marshal()([]byte,error) {
	return plist.MarshalIndent(c.dict, c.format, "	")
}

func ParseCodeResourcesFormFile(fileName string)(*CodeResourcesFile, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return ParseCodeResources(data)
}

func ParseCodeResources(data []byte)(*CodeResourcesFile, error) {
	m := &CodeResourcesFile{}
	dict := make(map[string]interface{})
	format, err := plist.Unmarshal(data, dict)
	if err != nil {
		return nil, err
	}
	m.dict = dict
	m.format = format
	return m, nil
}

func(c *CodeResourcesFile)GetFileHash(fileName string)[]byte {
	filesNode := (c.dict[ "files"]).(map[string]interface{})
	if data, ok := filesNode[fileName]; ok {
		switch data := data.(type) {
		case []byte:
			return data
		default:
			return nil
		}
	}
	return nil
}

func(c *CodeResourcesFile)UpdateFileHash(fileName string, fileBytes []byte) {
	filesNode := (c.dict[ "files"]).(map[string]interface{})
	sha1Hash := sha1.Sum(fileBytes)
	if _, ok := filesNode[fileName]; ok {
		filesNode[fileName] = sha1Hash
	}

	files2Node := (c.dict[ "files2"]).(map[string]interface{})
	if files2Node == nil {
		return
	}
	if node, ok := files2Node[fileName]; ok {
		switch node := node.(type) {
		case map[string]interface{}:
			sha256Hash := sha256.Sum256(fileBytes)
			node["hash"] = sha1Hash
			node["hash2"] = sha256Hash
		default:
		}
	}
}