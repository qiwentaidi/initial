package clients

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"initial/pkg/utils"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/panjf2000/ants/v2"
	"github.com/projectdiscovery/gologger"
)

var TlsConfig = &tls.Config{
	InsecureSkipVerify: true,             // 防止HTTPS报错
	MinVersion:         tls.VersionTLS10, // 最低支持TLS 1.0
}

// 跟随页面跳转最多10次
func DefaultClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: TlsConfig,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// 不跟随页面跳转
func NotFollowClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: TlsConfig,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func DefaultWithProxyClient(proxys string) *http.Client {
	client := DefaultClient()
	if proxys != "" {
		client, _ = SelectProxy(proxys, client)
	}
	return client
}

func NotFollowWithProxyClient(proxys string) *http.Client {
	client := NotFollowClient()
	if proxys != "" {
		client, _ = SelectProxy(proxys, client)
	}
	return client
}

func NewRequest(method, url string, headers map[string]string, body io.Reader, timeout int, closeRespBody bool, client *http.Client) (*http.Response, []byte, error) {
	requestTimeout := time.Duration(timeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	r, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, nil, err
	}
	r.Header.Set("User-Agent", utils.RandomUA())
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	resp, err := client.Do(r.WithContext(ctx))
	if err != nil {
		return nil, nil, err
	}
	if resp == nil {
		return nil, nil, errors.New("response is nil, possible network error or timeout")
	}
	if closeRespBody {
		defer resp.Body.Close()
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		// Handle "unexpected EOF" as a specific error case
		if err.Error() == "unexpected EOF" {
			return resp, bodyBytes, err
		}
		return nil, nil, err
	}

	return resp, bodyBytes, nil
}

func NewSimpleGetRequest(url string, client *http.Client) (*http.Response, []byte, error) {
	return NewRequest("GET", url, nil, nil, 10, true, client)
}

var (
	HTTP_PREFIX  = "http://"
	HTTPS_PREFIX = "https://"
)

// return error if host is not living
// or if host is live return http(s) url
func CheckProtocol(host string, client *http.Client) (string, error) {
	var result string
	if len(strings.TrimSpace(host)) == 0 {
		return result, fmt.Errorf("host %q is empty", host)
	}
	u, err := url.Parse(HTTP_PREFIX + host)
	if err != nil {
		return result, err
	}
	parsePort := u.Port()
	switch {
	case parsePort == "80":
		_, _, err := NewSimpleGetRequest(HTTP_PREFIX+host, client)
		if err != nil {
			return result, err
		}
		return HTTP_PREFIX + host, nil
	case parsePort == "443":
		_, _, err := NewSimpleGetRequest(HTTPS_PREFIX+host, client)
		if err != nil {
			return result, err
		}

		return HTTPS_PREFIX + host, nil

	default:
		_, _, err := NewSimpleGetRequest(HTTPS_PREFIX+host, client)
		if err == nil {
			return HTTPS_PREFIX + host, err
		}

		_, body, err := NewSimpleGetRequest(HTTP_PREFIX+host, client)
		if err == nil {
			if strings.Contains(string(body), "<title>400 The plain HTTP request was sent to HTTPS port</title>") {
				return HTTPS_PREFIX + host, nil
			}
			return HTTP_PREFIX + host, nil
		}

	}
	return "", fmt.Errorf("host %q is empty", host)
}

func GetTitle(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	if match := utils.RegTitle.FindSubmatch(body); len(match) > 1 {
		return strings.TrimSpace(utils.Str2UTF8(string(match[1])))
	}
	return ""
}

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
		protocolURL, err := CheckProtocol(url, DefaultClient())
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
