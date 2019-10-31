package appsign

import (
	"bufio"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

const headTag = `<tr><td valign="top"><a href="`
func DownAppleSrc(url string, outDir string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	buf := bufio.NewReader(resp.Body)
	for {
		line, err := buf.ReadString('\n')
		line = strings.TrimSpace(line)
		if strings.Index(line, headTag) == 0 {
			endIndex := strings.Index(line, `"><img src="/static`)
			if endIndex > 10 {
				err = SaveFile(url, outDir, line[len(headTag):endIndex])
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}
	return nil
}

func SaveFile(url, outDir, fileName string) error {
	resp, err := http.Get(url + fileName)
	if err != nil {
		return err
	}

	bin, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	d, err := os.Create(outDir + fileName)
	if err != nil {
		return err
	}
	d.Write(bin)
	d.Close()
	log.Printf(fileName)
	return nil
}

