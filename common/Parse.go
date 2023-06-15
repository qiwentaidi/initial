package common

import (
	"bufio"
	"log"
	"os"
)

func ParseURL(url, filepath string) (num int, targets []string) {
	if url != "" {
		targets = append(targets, removeDivision(url))
	} else if filepath != "" {
		file, err := os.Open(filepath)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		s := bufio.NewScanner(file)
		for s.Scan() {
			targets = append(targets, removeDivision(s.Text()))
		}
	}
	num = len(targets)
	return num, targets
}

func removeDivision(str string) (newStr string) {
	if str[len(str)-1:] == "/" {
		newStr = str[:len(str)-1]
		return newStr
	} else {
		return str
	}
}

func ParseICP(ICP, filepath string) (num int, targets []string) {
	if ICP != "" {
		targets = append(targets, ICP)
	} else if filepath != "" {
		file, err := os.Open(filepath)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		s := bufio.NewScanner(file)
		for s.Scan() {
			targets = append(targets, s.Text())
		}
	}
	num = len(targets)
	return num, targets
}
