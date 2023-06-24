package plugins

import (
	"net"
	"strings"
	"time"
)

func CheckMemcacheServer(address string, timeout float64) (result string) {
	conn, err := net.DialTimeout("tcp", address, time.Second*time.Duration(timeout))
	if err != nil {
		return ""
	}
	response, err := ConnResponse(conn, Memcached, timeout)
	if err != nil {
		return ""
	}
	if strings.Contains(string(response), "VERSION") {
		return "[+] Memcached unauthorized"
	} else {
		return "Memcached"
	}
}
