package plugins

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/stacktitan/smb/smb"
)

func CheckSmbAndNetbiosServer(host, port string) string {
	p, _ := strconv.Atoi(port)
	options := smb.Options{
		Host:     host,
		User:     "smb",
		Password: "123456",
		Domain:   "",
		Port:     p,
	}
	session, err := smb.NewSession(options, false)
	//fmt.Printf("err: %v\n", err)
	if err != nil {
		defer session.Close()
		if strings.Contains(fmt.Sprintf("%v", err), "Logon failed") {
			return "SMB"
		} else if strings.Contains(fmt.Sprintf("%v", err), "NetBIOS") {
			return "RPC"
		} else {
			return ""
		}
	} else {
		defer session.Close()
		return "[+] SMB smb:123456 连接成功"
	}
}
