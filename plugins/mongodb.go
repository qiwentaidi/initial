package plugins

import (
	"net"
	"strings"
	"time"
)

func CheckMongodbUnauth(address string, timeout float64) string {
	var matched bool
	conn, err := net.DialTimeout("tcp", address, time.Second*time.Duration(timeout))
	if err != nil {
		return ""
	}
	_, err = conn.Write(MongoDB)
	if err != nil {
		matched = false
	}
	// 接收响应或数据包
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		matched = false
	}
	// 分析接收到的响应或数据包，提取协议信息
	response := string(buf[:n])
	if strings.Contains(response, "id") {
		matched = true
	} else {
		matched = false
	}
	if matched {
		return "[+] Mongodb unauthorized"
	} else {
		return "Mongodb"
	}
}
