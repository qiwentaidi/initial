package utils

import (
	"bufio"
	"initial/pkg/clients"
	"os"
	"strings"
	"sync"

	"github.com/panjf2000/ants/v2"
	"github.com/projectdiscovery/gologger"
)

func ParseURL(url string, filepath string) []string {
	var targets []string
	temps := parseInput(url, filepath)
	var wg sync.WaitGroup
	single := make(chan struct{})
	retChan := make(chan string)
	go func() {
		for url := range retChan {
			targets = append(targets, url)
		}
		close(single)
	}()
	checkURL := func(url string) {
		if strings.HasPrefix(url, "http") {
			retChan <- url
			return
		}
		protocolURL, err := clients.CheckProtocol(url, clients.DefaultClient())
		if err == nil {
			retChan <- protocolURL
		}
	}
	threadPool, _ := ants.NewPoolWithFunc(50, func(target interface{}) {
		t := target.(string)
		checkURL(t)
		wg.Done()
	})
	defer threadPool.Release()
	for _, temp := range temps {
		wg.Add(1)
		threadPool.Invoke(temp)
	}
	wg.Wait()
	close(retChan)
	<-single
	return targets
}

func parseInput(urls string, filepath string) []string {
	var targets []string
	if urls != "" {
		targets = append(targets, urls)
	} else if filepath != "" {
		file, err := os.Open(filepath)
		if err != nil {
			gologger.Error().Msgf("Could not open file %s: %v\n", filepath, err)
			return targets
		}
		defer file.Close()
		s := bufio.NewScanner(file)
		for s.Scan() {
			targets = append(targets, s.Text())
		}
	}
	return targets
}

// 去除末尾的/
func removeDivision(str string) (newStr string) {
	if str[len(str)-1:] == "/" {
		newStr = str[:len(str)-1]
		return newStr
	} else {
		return str
	}
}
