package main

import (
	"fmt"
	"initial/burst"
	"initial/color"
	"initial/common"
	"initial/info"
	"initial/plugins"
	"initial/webscan"
	"time"
)

func main() {
	cf := common.Flag()
	// 整理目标
	infos := common.ParseFile(cf.Info.CompanyName, cf.Info.CompanyFile)
	urlNum, urlTargets := common.ParseURL(cf.Scan.Url, cf.Scan.UrlFile)
	ips := common.ParseIPs(cf.Scan.Ip, cf.Scan.IpFile)
	domains := common.ParseFile(cf.Burst.Domain, cf.Burst.DomainFile)
	// 判断进行什么操作
	if len(infos) > 0 {
		info.InitTask(&cf.Info, infos)
	} else if urlNum > 0 {
		webscan.FingerScan(urlTargets, &cf.Scan)
	} else if len(ips) > 0 {
		start := time.Now()
		fmt.Printf(color.Cyan+"[*] 正在进行端口扫描,扫描端口总数%v,超时时长设置为%vs...\n"+color.White, len(ips)*len(common.ParsePort(cf.Scan.Ports)), cf.Scan.Timeout)
		plugins.PortScan(ips, common.ParsePort(cf.Scan.Ports), cf.Scan.Thread, cf.Scan.Timeout)
		fmt.Printf(color.Cyan+"[*] 扫描结束,耗时: %s"+color.White, time.Since(start))
	} else if len(domains) > 0 {
		start := time.Now()
		burst.SubdomainBurst(domains, &cf.Burst)
		fmt.Printf(color.Cyan+"[*] 暴破结束,耗时: %s"+color.White, time.Since(start))
	}
}
