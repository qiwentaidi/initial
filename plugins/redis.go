package plugins

import (
	"net"
	"strings"
	"time"
)

func CheckRedisUnauth(address string, timeout float64) string {
	conn, err := net.DialTimeout("tcp", address, time.Second/time.Duration(timeout))
	if err != nil {
		return ""
	}
	_, err = conn.Write(Reids)
	if err != nil {
		return ""
	}
	buf := make([]byte, 1024)
	n, err1 := conn.Read(buf)
	if err1 != nil {
		return ""
	}
	response := string(buf[:n])
	if strings.Contains(response, "+PONG") {
		return "[+] " + address + " Redis unauthorized"
	} else {
		return address + " Redis"
	}
}
