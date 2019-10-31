package appsign

import (
	"howett.net/plist"
	"io/ioutil"
)

type InfoFile struct {
	dict map[string]interface{}
	format int
}

func(i *InfoFile)Marshal()([]byte, error) {
	return plist.MarshalIndent(i.dict, i.format, "	")
}

func(i *InfoFile)ExecutableName()string {
	if name, ok := i.dict["CFBundleExecutable"]; ok {
		return name.(string)
	}
	return ""
}

const bundleIdName = "CFBundleIdentifier"
func(i *InfoFile) BundleId()string {
	if name, ok := i.dict[bundleIdName]; ok {
		return name.(string)
	}
	return ""
}

func(i *InfoFile) ReplaceBundleId(name string) bool {
	if oldName := i.BundleId(); oldName != name {
		i.dict[bundleIdName] = name
		return true
	}
	return false
}

func ParseInfoFromFile(fileName string)(*InfoFile, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return ParseInfo(data)
}

func ParseInfo(data []byte)(*InfoFile, error) {
	m := &InfoFile{}
	dict := make(map[string]interface{})
	format, err := plist.Unmarshal(data, dict)
	if err != nil {
		return nil, err
	}
	m.dict = dict
	m.format = format
	return m, nil
}