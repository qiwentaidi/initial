package webscan

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"
)

// request返回的信息
type CheckDatas struct {
	Status     int    // 状态码
	Headers    string // headers信息
	Title      string // 标题
	Body       []byte // 主体内容
	FaviconMd5 string // md5适用hunter
}

// MatchFinger的结果存放在这
type FingerResult struct {
	url           string
	status        int
	contentLength int
	title         string
	fingerprint   []string
	detection     []string
}

// Poc的内容
type PocRule struct {
	Name     string
	Requests []struct {
		Method          string            `yaml:"method"`          // 请求方法
		Headers         map[string]string `yaml:"headers"`         // 请求头
		Path            []string          `yaml:"path"`            // 路径
		Params          map[string]string `yaml:"params"`          // 参数
		FollowRedirects bool              `yaml:"followredirects"` // 是否跟随跳转
		Matchers        string            `yaml:"matchers"`        // 响应内容，验证
	} `yaml:"requests"`
}

var (
	wg       sync.WaitGroup
	active   bool
	scanFile *csv.Writer
)

// 指纹扫描
func FingerScan(targets []string, thread int, isoepn bool) {
	file, _ := os.OpenFile(fmt.Sprintf("./report/scan_%v.csv", time.Now().Format("2006-01-02 15_04_05")), os.O_CREATE|os.O_RDWR, os.ModePerm) // 创建结果文件
	file.WriteString("\xEF\xBB\xBF")
	scanFile = csv.NewWriter(file)
	active = isoepn
	limiter := make(chan bool, thread) // 限制协程数量
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout: time.Second * 3,
		},
	}
	for _, t := range targets {
		wg.Add(1)
		limiter <- true
		go MatchFinger(t, client, limiter, &wg)
	}
	wg.Wait()
}

// 匹配对应的指纹信息
func MatchFinger(url string, client *http.Client, limiter chan bool, wg *sync.WaitGroup) {
	var fr FingerResult
	var matched bool // 判断指纹匹配状态
	defer wg.Done()
	data := GetResponse(url, client)
	if data.Status != 0 { // 响应正常
		fr.url = url
		fr.status = data.Status
		fr.contentLength = len(data.Body)
		fr.title = data.Title
		for _, rule := range RuleDatas {
			switch rule.Type {
			case "body":
				matched, _ = regexp.MatchString(rule.Rule, string(data.Body))
			case "headers":
				matched, _ = regexp.MatchString(rule.Rule, data.Headers)
			default:
				matched, _ = regexp.MatchString(rule.Rule, data.FaviconMd5)
			}
			if matched {
				fr.fingerprint = append(fr.fingerprint, rule.Name)
				matched = false
			}
		}
		if active {
			sensitive := ActiveDetection(url, client)
			if len(sensitive) > 0 {
				fr.detection = append(fr.detection, sensitive...)
			}
		}
		fr.fingerprint = RemoveDuplicates(fr.fingerprint)
		fmt.Printf("%v	", fr.url)
		if fr.status >= 200 && fr.status < 300 {
			fmt.Printf("\033[32m[%v] ", fr.status)
		} else if fr.status >= 400 && fr.status < 500 {
			fmt.Printf("\033[35m[%v] ", fr.status)
		} else if fr.status > 500 {
			fmt.Printf("\033[31m[%v] ", fr.status)
		} else {
			fmt.Printf("[%v] ", fr.status)
		}
		fmt.Printf("\033[34m[%v] ", fr.contentLength)
		fmt.Printf("\033[37m[%v] ", fr.title)
		fmt.Printf("\033[36m%v ", fr.fingerprint)
		fmt.Printf("\033[35m%v\033[37m\n", fr.detection)
		scanFile.Write([]string{fr.url, fmt.Sprintf("%v", fr.status), fmt.Sprintf("%v", fr.contentLength), fr.title, fmt.Sprintf("%v", fr.fingerprint), fmt.Sprintf("%v", fr.detection)})
		scanFile.Flush()
		<-limiter
	} else { // 响应超时处理
		fmt.Printf("%v\t[%d]\n", url, 0)
		scanFile.Write([]string{fr.url, "0"})
		scanFile.Flush()
		<-limiter
	}
}

func GetResponse(url string, client *http.Client) *CheckDatas {
	var checkdatas CheckDatas // 将响应头和响应头的数据存储到结构体中
	// 发送一个普通的GET请求获取响应包以及响应头的内容
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("Cookie", "rememberMe=1") // 检测shiro
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, _ := client.Do(req.WithContext(ctx))
	if resp != nil && resp.StatusCode != 302 { // 过滤重定向次数过多的
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()
		// 把响应包的内容，标题,状态码赋值给结构体
		re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
		match := re.FindSubmatch(body)
		if len(match) > 1 {
			checkdatas.Title = string(match[1])
		} else {
			checkdatas.Title = ""
		}
		checkdatas.Body = body
		checkdatas.Status = resp.StatusCode
		for key, value := range resp.Header {
			checkdatas.Headers += fmt.Sprintf("%v:%v", key, value)
		}
		checkdatas.FaviconMd5 = FaviconMd5(url, client, ctx)
	}
	return &checkdatas
}

// FaviconMd5 获取favicon md5值
func FaviconMd5(url string, client *http.Client, ctx context.Context) string {
	r, _ := http.NewRequest("GET", url+"/favicon.ico", nil)
	r2, _ := client.Do(r.WithContext(ctx))
	if r2 != nil {
		b, _ := io.ReadAll(r2.Body)
		hash := md5.New()
		io.WriteString(hash, string(b))
		return hex.EncodeToString(hash.Sum(nil))
	} else {
		return ""
	}
}

// 判断client客户端是否需要跟随跳转
func CheckFollowRedirects(status bool, client *http.Client) {
	if !status {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不跟随页面跳转
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return nil
		}
	}
}

// 数组去重
func RemoveDuplicates[T comparable](arr []T) []T {
	encountered := map[T]bool{}
	result := []T{}
	for _, v := range arr {
		if !encountered[v] {
			// Record this element as an encountered element.
			encountered[v] = true
			// Append to result slice.
			result = append(result, v)
		}
	}
	// Return the new slice.
	return result
}
