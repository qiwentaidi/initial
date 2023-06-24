package common

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// "192.168.1.1\n" +
// "192.168.1.1/8\n" +
// "192.168.1.1/16\n" +
// "192.168.1.1/24\n" +
// "192.168.1.1,192.168.1.2\n" +
// "192.168.1.1-192.168.255.255\n" +
// "192.168.1.1-255"

func ParseIPs(ipString string, filepath string) (ips []string) {
	if filepath != "" {
		ips = append(ips, ReadFile(filepath)...)
	} else if ipString != "" {
		ips = append(ips, ParseIP(ipString)...)
	}
	return ips
}

func ParseIP(ipString string) []string {
	var result []string
	if strings.Contains(ipString, "-") {
		result = append(result, parseIP1(ipString)...)
	}
	ipArray := strings.Split(ipString, ",")
	for _, ip := range ipArray {
		if strings.Contains(ip, "/") {
			parsedIPs, err := parseCIDR(ip)
			if err != nil {
				fmt.Println("Error parsing CIDR:", err)
				continue
			}
			result = append(result, parsedIPs...)
		} else {
			result = append(result, parseSingleIP(ip)...)
		}
	}
	return result
}

func ReadFile(filepath string) []string {
	file, err := os.Open(filepath)
	if err != nil {
		fmt.Printf("Open %s error, %v", filepath, err)
		os.Exit(0)
	}
	defer file.Close()
	var content []string
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		content = append(content, ParseIP(scanner.Text())...)
	}
	return content
}

func parseCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func parseSingleIP(ip string) []string {
	return []string{ip}
}

// 解析ip段: 192.168.111.1-255
// 192.168.111.1-192.168.112.255
func parseIP1(ip string) []string {
	IPRange := strings.Split(ip, "-")
	testIP := net.ParseIP(IPRange[0])
	var AllIP []string
	if len(IPRange[1]) < 4 {
		Range, err := strconv.Atoi(IPRange[1])
		if testIP == nil || Range > 255 || err != nil {
			return nil
		}
		SplitIP := strings.Split(IPRange[0], ".")
		ip1, err1 := strconv.Atoi(SplitIP[3])
		ip2, err2 := strconv.Atoi(IPRange[1])
		PrefixIP := strings.Join(SplitIP[0:3], ".")
		if ip1 > ip2 || err1 != nil || err2 != nil {
			return nil
		}
		for i := ip1; i <= ip2; i++ {
			AllIP = append(AllIP, PrefixIP+"."+strconv.Itoa(i))
		}
	} else {
		SplitIP1 := strings.Split(IPRange[0], ".")
		SplitIP2 := strings.Split(IPRange[1], ".")
		if len(SplitIP1) != 4 || len(SplitIP2) != 4 {
			return nil
		}
		start, end := [4]int{}, [4]int{}
		for i := 0; i < 4; i++ {
			ip1, err1 := strconv.Atoi(SplitIP1[i])
			ip2, err2 := strconv.Atoi(SplitIP2[i])
			if ip1 > ip2 || err1 != nil || err2 != nil {
				return nil
			}
			start[i], end[i] = ip1, ip2
		}
		startNum := start[0]<<24 | start[1]<<16 | start[2]<<8 | start[3]
		endNum := end[0]<<24 | end[1]<<16 | end[2]<<8 | end[3]
		for num := startNum; num <= endNum; num++ {
			ip := strconv.Itoa((num>>24)&0xff) + "." + strconv.Itoa((num>>16)&0xff) + "." + strconv.Itoa((num>>8)&0xff) + "." + strconv.Itoa((num)&0xff)
			AllIP = append(AllIP, ip)
		}
	}
	return AllIP
}
