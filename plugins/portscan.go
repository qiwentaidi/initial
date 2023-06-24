package plugins

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

var result string //其他端口协议的检测结果

// 端口扫描
func PortScan(hosts []string, ports []int, thread int, timeout float64) {
	var wg sync.WaitGroup
	limiter := make(chan bool, thread)
	completed := make(chan bool)
	totalIterations := len(hosts) * len(ports)
	completedIterations := 0
	counter := sync.Mutex{}
	for _, port := range ports {
		for _, host := range hosts {
			wg.Add(1)
			limiter <- true
			go func(h string, p int) {
				address := fmt.Sprintf("%s:%d", h, p)
				defer func() {
					wg.Done()
					<-limiter
					counter.Lock()
					completedIterations++
					if completedIterations == totalIterations {
						completed <- true
					}
					counter.Unlock()
				}()
				if conn, err := net.DialTimeout("tcp", address, time.Second*time.Duration(timeout)); err == nil {
					defer conn.Close()
					PortFingerprint(conn, address, timeout)
				}
			}(host, port)
		}
	}
	go func() {
		wg.Wait()
		completed <- true
	}()
	<-completed
}

func PortFingerprint(conn net.Conn, address string, timeout float64) {
	var matched bool
	response, _ := ConnResponse(conn, []byte("GET / HTTP/1.1\r\nHost: "+address+"\r\n\r\n"), timeout)
	// Create a map to store the matched status for each address
	matchedStatus := make(map[string]bool)
	for _, rule := range PortRules {
		if rule.Format == "string" {
			matched, _ = regexp.MatchString(rule.Rule, string(response))
		} else { // hex string
			matched, _ = regexp.MatchString(rule.Rule, hex.EncodeToString(response))
		}
		if matched {
			switch rule.Name {
			case "Redis":
				fmt.Println(CheckRedisUnauth(address, timeout))
			case "Mongodb":
				fmt.Println(CheckMongodbUnauth(address, timeout))
			default:
				fmt.Printf("%s %s\n", address, rule.Name)
			}
			matchedStatus[address] = true
			matched = false
		}
	}

	// 获取不到指纹的走这边
	if _, ok := matchedStatus[address]; !ok {
		host, port := strings.Split(address, ":")[0], strings.Split(address, ":")[1]
		if result = CheckMssqlServer(host, port, timeout); result != "" {
			fmt.Println(address + " " + result)
			return
		}
		if result = CheckOracleServer(host, port, timeout); result != "" {
			fmt.Println(address + " " + result)
			return
		}
		if result = CheckMemcacheServer(address, timeout); result != "" {
			fmt.Println(address + " " + result)
			return
		}
		if result = CheckMqttServer(address, timeout); result != "" {
			fmt.Println(address + " " + result)
			return
		}
		if result = CheckSmbAndNetbiosServer(host, port); result != "" {
			fmt.Println(address + " " + result)
			return
		} else {
			fmt.Printf("%s Unknown\n", address)
		}
	}
	// fmt.Printf("response: %v\n", response)
	// fmt.Printf("string(response): %v\n", string(response))
}

// 获取部分指纹信息
func ConnResponse(conn net.Conn, b []byte, timeout float64) (response []byte, err error) {
	// 使用 context 包设置 3 秒超时
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	// 发送请求
	_, err = conn.Write(b)
	if err != nil {
		//fmt.Printf("Failed to send request - %s\n", err)
		return []byte{}, err
	}
	// 接收响应并设置超时
	buf := make([]byte, 4096)
	responseCh := make(chan int, 1)
	go func() {
		n, err1 := conn.Read(buf)
		if err1 != nil {
			//fmt.Printf("Failed to send request - %s\n", err1)
			responseCh <- 0
			return
		}
		// 分析接收到的响应或数据包，提取协议信息
		response = buf[:n]
		responseCh <- 1
	}()

	// 等待接收响应或超时
	select {
	case <-ctx.Done():
		//fmt.Printf("Timeout receiving response - %s\n", ctx.Err())
		return []byte{}, ctx.Err()
	case ok := <-responseCh:
		if ok == 1 {
			return response, nil
		} else {
			return []byte{}, fmt.Errorf("failed to receive response")
		}
	}
}
