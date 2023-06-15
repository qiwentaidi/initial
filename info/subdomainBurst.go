package info

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// request返回的信息
type CheckDatas struct {
	Status int    // 状态码
	Server string // headers信息
	Title  string // 标题
}

var (
	subdomainDic    []string
	NumOfIPResolved = make(map[string]int)
	mutex           sync.Mutex
)

// 读取子域字典
func RegDomain(filepath string) []string {
	f, err := os.OpenFile(filepath, os.O_RDONLY, 0644)
	if err != nil {
		log.Fatal(err)
	} else {
		s := bufio.NewScanner(f)
		for s.Scan() {
			subdomainDic = append(subdomainDic, s.Text())
		}
	}
	f.Close()
	return subdomainDic
}

// 子域名暴破
func SubdomainBurst(sub, domain string, limier chan bool, wg *sync.WaitGroup) {
	subdomain := sub + "." + domain
	defer wg.Done()
	addr, err := net.LookupHost(subdomain)
	if err == nil {
		addrs := removeDuplicates(addr) // 去重
		for _, ip := range addrs {
			mutex.Lock()
			NumOfIPResolved[ip]++
			if NumOfIPResolved[ip] > 3 { // 解析到该IP3次以上加入黑名单
				addrs = removeElement(addrs, ip)
			}
			mutex.Unlock()
		}
		if len(addrs) > 0 {
			arrStr := strings.Join(addrs, "  ")
			cd := GetResponse(subdomain)
			if cd.Status >= 200 && cd.Status < 300 {
				fmt.Printf("\033[32m	%v	 %v\033[37m", cd.Status, subdomain)
			} else if cd.Status >= 400 && cd.Status < 500 {
				fmt.Printf("\033[35m	%v	 %v\033[37m", cd.Status, subdomain)
			} else if cd.Status > 500 {
				fmt.Printf("\033[31m	%v	 %v\033[37m", cd.Status, subdomain)
			} else {
				fmt.Printf("	%v	 %v", cd.Status, subdomain)
			}
			fmt.Println("		" + cd.Server + "		" + arrStr)
		}
	}
	<-limier
}

func GetResponse(domain string) *CheckDatas {
	var checkdatas CheckDatas // 将响应头和响应头的数据存储到结构体中
	client := &http.Client{}
	// 发送一个普通的GET请求获取响应包以及响应头的内容
	req, err := http.NewRequest("GET", "http://"+domain, nil)
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36")
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, _ := client.Do(req.WithContext(ctx))
	if resp != nil {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		// 把响应包的内容，标题,状态码赋值给结构体
		re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
		match := re.FindSubmatch(body)
		if len(match) > 1 {
			checkdatas.Title = string(match[1])
		} else {
			checkdatas.Title = ""
		}
		checkdatas.Status = resp.StatusCode
		for key, value := range resp.Header {
			if key == "Server" {
				checkdatas.Server = fmt.Sprintf("%v", value)
				break
			}
		}
		if checkdatas.Server == "" {
			checkdatas.Server = "	"
		}
	}
	return &checkdatas
}
