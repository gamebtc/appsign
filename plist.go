package appsign

import (
	"encoding/base64"
	"errors"
	"strconv"
	"time"

	"github.com/beevik/etree"
	//"github.com/DHowett/go-plist"
	//log "github.com/sirupsen/logrus"
)

const PListFormatBinary = 0
const PListFormatXml = 1

type PlistItem struct {
	Key string
	Value interface{}
}

type PlistDict struct {
	Items []*PlistItem
}

func(d *PlistDict)GetValue(key string)(interface{}, bool) {
	for i := len(d.Items) - 1; i >= 0; i-- {
		if d.Items[i].Key == key {
			return d.Items[i].Value, true
		}
	}
	return nil, false
}

func LoadPlistDict(text string)(*PlistDict,error) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(text)
	if err != nil {
		return nil, err
	}
	root := doc.SelectElement("dict")
	return ParsePlistDict(root)
}

func ParsePlistDict(node *etree.Element)(*PlistDict, error) {
	var key string
	var items []*PlistItem
	for _, item := range node.ChildElements() {
		if item.Tag == "key" {
			key = item.Text()
		} else {
			if key == "" {
				return nil, errors.New("format error:" + item.Tag)
			}
			value, err := ParseXmlValue(item)
			if err != nil {
				return nil, err
			}
			//log.Printf("key:%v,value:%v", key, value)
			items = append(items, &PlistItem{key, value})
			key = ""
		}
	}
	return &PlistDict{Items: items}, nil
}

func ParseXmlValue(item *etree.Element)(interface{},  error) {
	switch item.Tag {
	case "string":
		return item.Text(), nil
	case "array":
		return ParsePlistArray(item)
	case "date":
		return time.Parse(time.RFC3339, item.Text())
	case "false":
		return false, nil
	case "true":
		return true, nil
	case "data":
		return base64.StdEncoding.DecodeString(item.Text())
	case "dict":
		return ParsePlistDict(item)
	case "integer":
		value, err := strconv.Atoi(item.Text())
		if err == nil {
			return value, nil
		}
		return strconv.ParseFloat(item.Text(), 10)
	default:
		return nil, errors.New("Undefined type:" + item.Tag)
	}
}

func ParsePlistArray(node *etree.Element)(interface{}, error) {
	nodes := node.ChildElements()

	if stringArray, ok := ParseStringArray(nodes); ok {
		return stringArray, nil
	}
	if dataArray, ok := ParseDataArray(nodes); ok {
		return dataArray, nil
	}

	var values []interface{}
	for _, item := range nodes {
		value, err := ParseXmlValue(item)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

func ParseStringArray(nodes []*etree.Element)([]string, bool) {
	for _, item := range nodes {
		if item.Tag != "string" {
			return nil, false
		}
	}
	values := make([]string, len(nodes))
	for i, item := range nodes {
		values[i] = item.Text()
	}
	return values, true
}

func ParseDataArray(nodes []*etree.Element)([][]byte, bool) {
	for _, item := range nodes {
		if item.Tag != "data" {
			return nil, false
		}
	}
	values := make([][]byte, len(nodes))
	for i, item := range nodes {
		v, _ := base64.StdEncoding.DecodeString(item.Text())
		values[i] = v
	}
	return values, true
}