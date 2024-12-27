package clients

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"time"

	"golang.org/x/net/proxy"
)

// 选择代理模式，返回http.client
func SelectProxy(proxys string, client *http.Client) (*http.Client, error) {
	parsedURL, err := url.Parse(proxys)
	if err != nil {
		return nil, err
	}
	if parsedURL.Scheme == "http" || parsedURL.Scheme == "https" {
		client.Transport = &http.Transport{
			Proxy:               http.ProxyURL(parsedURL),
			TLSClientConfig:     TlsConfig, // 防止HTTPS报错
			TLSHandshakeTimeout: time.Second * 10,
		}
	} else if parsedURL.Scheme == "socks5" {
		auth := &proxy.Auth{User: parsedURL.User.Username(), Password: ""} // 提取用户名
		if password, ok := parsedURL.User.Password(); ok {
			auth.Password = password // 提取密码
		}
		dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("%v:%v", parsedURL.Hostname(), parsedURL.Port()), auth, proxy.Direct) //"127.0.0.1:9742"
		if err != nil {
			return nil, errors.New("socks address not available")
		}
		client.Transport = &http.Transport{
			TLSClientConfig:     TlsConfig, // 防止HTTPS报错
			Dial:                dialer.Dial,
			TLSHandshakeTimeout: time.Second * 3,
			// 设置sock5
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := dialer.Dial(network, addr)
				if err != nil {
					return nil, err
				}
				return conn, nil
			},
		}
	} else {
		return nil, errors.New("unsupported proxy type") // 添加对不支持的代理类型的处理
	}
	return client, nil
}
