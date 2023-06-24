package burst

import (
	"context"
	"crypto/tls"
	"fmt"
	"initial/color"
	"initial/common"
	"io"
	"log"
	"net"
	"net/http"
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
	Lenth  int    // 内容长度
}

var (
	IPResolved      = make(map[string]int)
	mutex           sync.Mutex
	secdomains      []string
	wg              sync.WaitGroup
	request_timeout float64
)

// 子域名暴破  subfile string, thead, level int, timeout float64
func SubdomainBurst(domains []string, burst *common.Burst) {
	request_timeout = burst.Timeout
	limier := make(chan bool, burst.Thread)
	subs := common.ParseFile("", burst.SubFile)
	fmt.Printf(color.Cyan+"[*] 正在进行子域名暴破,子域字典路径为%v,已加载字典数量%d ...\n"+color.White, burst.SubFile, len(subs))
	for _, domain := range domains {
		if domain != "" {
			for _, sub := range subs {
				wg.Add(1)
				limier <- true
				go Burst(sub, domain, limier, &wg)
			}
		}
	}
	wg.Wait() // 等待所有任务完成
	for i := 1; i <= burst.Level; i++ {
		if burst.Level > 1 {
			temp := secdomains
			for _, domain := range temp {
				secdomains = []string{}
				if domain != "" {
					for _, sub := range subs {
						wg.Add(1)
						limier <- true
						go Burst(sub, domain, limier, &wg)
					}
				}
			}
			wg.Wait() // 等待所有任务完成
		}
	}
}

func Burst(sub, domain string, limier chan bool, wg *sync.WaitGroup) {
	subdomain := sub + "." + domain
	defer wg.Done()
	addr, err := net.LookupHost(subdomain)
	if err == nil {
		addrs := common.RemoveDuplicates(addr) // 去重
		for _, ip := range addrs {
			mutex.Lock()
			IPResolved[ip]++
			if IPResolved[ip] > 3 { // 解析到该IP3次以上加入黑名单
				addrs = common.RemoveElement(addrs, ip)
			}
			mutex.Unlock()
		}
		if len(addrs) > 0 {
			arrStr := strings.Join(addrs, "	") // 转换成字符串
			cd := HTTPMoudle(subdomain)
			if cd.Status >= 200 && cd.Status < 300 {
				fmt.Printf("%v [\033[32m%v\033[37m] [\033[34m%s\033[37m] [%d] %s [%s]\n", subdomain, cd.Status, cd.Title, cd.Lenth, cd.Server, arrStr)
			} else if cd.Status >= 300 && cd.Status < 400 {
				fmt.Printf("%v [\033[33m%v\033[37m] [\033[34m%s\033[37m] [%d] %s [%s]\n", subdomain, cd.Status, cd.Title, cd.Lenth, cd.Server, arrStr)
			} else if cd.Status >= 400 && cd.Status < 500 {
				fmt.Printf("%v [\033[35m%v\033[37m] [\033[34m%s\033[37m] [%d] %s [%s]\n", subdomain, cd.Status, cd.Title, cd.Lenth, cd.Server, arrStr)
			} else {
				fmt.Printf("%v [%v] [%s] [%d] %s [%s]\n", subdomain, cd.Status, cd.Title, cd.Lenth, cd.Server, arrStr)
			}
			secdomains = append(secdomains, subdomain)
		}
	}
	<-limier
}

func HTTPMoudle(domain string) *CheckDatas {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout: time.Second * time.Duration(request_timeout),
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不跟随页面跳转
		},
	}
	cd := GetResponse("http://"+domain, client)
	if cd.Status >= 200 && cd.Status < 500 {
		return cd
	} else {
		cd = GetResponse("https://"+domain, client)
		return cd
	}
}

func GetResponse(url string, client *http.Client) *CheckDatas {
	var checkdatas CheckDatas // 将响应头和响应头的数据存储到结构体中
	// 先发送一个HTTP请求获取响应包以及响应头的内容
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36")
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(request_timeout)*time.Second)
	defer cancel()
	resp, _ := client.Do(req.WithContext(ctx))
	if resp != nil {
		checkdatas.Status = resp.StatusCode
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		checkdatas.Lenth = len(body)
		// 把响应包的内容，标题,状态码赋值给结构体
		re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
		match := re.FindSubmatch(body)
		if len(match) > 1 {
			checkdatas.Title = string(match[1])
		} else {
			checkdatas.Title = ""
		}
		for key, value := range resp.Header {
			if key == "Server" {
				checkdatas.Server = fmt.Sprintf("%v", value)
				break
			}
		}
	}
	return &checkdatas
}
