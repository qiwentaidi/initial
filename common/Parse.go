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

func ParseFile(target, filepath string) (targets []string) {
	if target != "" {
		targets = append(targets, target)
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
