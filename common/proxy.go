package common

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

var (
	username string
	password string
)

// 选择代理模式，返回http.client
func SelectProxy(proxyaddress, auth string) (client *http.Client) {
	moudle, address := strings.Split(proxyaddress, "://")[0], strings.Split(proxyaddress, "://")[1] // http | sock
	if moudle == "http" {
		urli := url.URL{}
		urlproxy, _ := urli.Parse(proxyaddress) //"https://127.0.0.1:9743"
		client = &http.Client{
			Transport: &http.Transport{
				Proxy:               http.ProxyURL(urlproxy),
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // 防止HTTPS报错
				TLSHandshakeTimeout: time.Second * 3,
			},
		}
	} else {
		if auth != "" {
			username, password = strings.Split(auth, ":")[0], strings.Split(auth, ":")[1]
		}
		auth := &proxy.Auth{User: username, Password: password}
		dialer, err := proxy.SOCKS5("tcp", address, auth, proxy.Direct) //"127.0.0.1:9742"
		if err != nil {
			log.Fatal(err)
			return nil
		}
		httpTransport := &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // 防止HTTPS报错
			Dial:                dialer.Dial,
			TLSHandshakeTimeout: time.Second * 3,
		}
		client = &http.Client{Transport: httpTransport}
		// 设置sock5
		httpTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.Dial(network, addr)
			if err != nil {
				log.Fatal(err)
				return nil, err
			}
			return conn, nil
		}
	}
	return client
}
