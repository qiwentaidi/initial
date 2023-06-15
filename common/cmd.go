package common

import (
	"encoding/csv"
	"fmt"
	"initial/info"
	"initial/webscan"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/olekukonko/tablewriter"
)

var (
	asset_icp    = make(map[string]int64)
	asset_domain = make(map[string]int64)
	wg           sync.WaitGroup
)

func ExecMethod(cf *CmdFlag) {
	// 整理目标
	infoNum, infoTargets := ParseICP(cf.Info.CompanyName, cf.Info.CompanyFile)
	scanNum, scanTargets := ParseURL(cf.Scan.Url, cf.Scan.UrlFile)
	// 判断进行什么操作
	if infoNum > 0 {
		if cf.Info.WhollySubsidiary {
			fmt.Println("\033[36m[+] 正在查询全资子公司以及反查ICP域名备案信息 ...\033[37m")
			for _, t := range infoTargets {
				fuzzname, subsidiaries := info.SearchSubsidiary(t)
				if t != fuzzname {
					infoTargets = info.ReplaceElement(infoTargets, t, fuzzname) // 将错误的名称替换成正确的ICP(含误报概率)
				}
				infoTargets = append(infoTargets, subsidiaries...)
				time.Sleep(time.Millisecond * 2000)
			}
		}
		if len(infoTargets)+len(info.TargetDomain) > 0 {
			os.Mkdir("./report", 0664)
			fmt.Printf("\033[36m[+] 正在进行hunter资产数量查询,查询总数:%d ...\033[37m\n", len(infoTargets)+len(info.TargetDomain))
			file, _ := os.OpenFile(fmt.Sprintf("./report/info_%v.csv", time.Now().Format("2006-01-02 15_04_05")), os.O_CREATE|os.O_RDWR, os.ModePerm) // 创建结果文件
			file.WriteString("\xEF\xBB\xBF")
			info.Result = csv.NewWriter(file)
			bar := pb.StartNew(len(infoTargets) + len(info.TargetDomain))
			for _, t := range infoTargets {
				bar.Increment()
				seach_icp(t)
			}
			for _, domain := range info.TargetDomain {
				bar.Increment()
				seach_domain(domain)
			}
			bar.Finish()
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"公司名称OR域名", "HUNTER资产数量"})
			for _, v := range info.AssetData {
				table.Append(v)
			}
			table.Render() // Send output
			fmt.Printf("\033[36m%v\033[37m\n", info.Restquota)
		}
		if cf.Info.BurstFile != "" {
			limier := make(chan bool, 100)
			subdomains := info.RegDomain(cf.Info.BurstFile)
			count := len(subdomains)
			fmt.Printf("\033[36m[+] 正在进行子域名暴破,字典路径为%v,已加载字典数量%d ...\033[37m\n", cf.Info.BurstFile, count)
			fmt.Println("	Code	 Subdomain		  	Server			Ip Address")
			fmt.Println("——————————————————————————————————————————————————————————————————————————————————————")
			for domain := range asset_domain {
				domain = strings.Split(domain, "=\"")[1]
				domain = domain[:len(domain)-1]
				for _, sub := range subdomains {
					wg.Add(1)
					go func(s, d string) {
						limier <- true
						info.SubdomainBurst(s, d, limier, &wg)
					}(sub, domain)
				}
			}
			wg.Wait()
		}
		// 全部导出
		if cf.Info.Export {
			fmt.Printf("需要导出查询的ICP名称共:	\033[35m%d个\033[37m,需要导出查询的查询的域名共:	\033[35m%d个\033[37m\n", len(asset_icp), len(asset_domain))
			switch cf.Info.Moudle {
			case 0:
				fmt.Println("[!]当前导出模式为	-	仅导出ICP资产")
			case 1:
				fmt.Println("[!]当前导出模式为	-	仅导出域名资产")
			case 2:
				fmt.Println("[!]当前导出模式为	-	导出ICP和域名资产")
			default:
				panic("导出模式错误")
			}
			AssetExport(cf.Info.Moudle)
		}
	} else if scanNum > 0 {
		webscan.FingerScan(scanTargets, cf.Scan.Thread, cf.Scan.ActiveDetection)
	}
}

func seach_icp(company string) {
	time.Sleep(time.Millisecond * 2000)
	str := fmt.Sprintf("icp.name=\"%v\"", company)
	asset, num := info.SearchTotal(str)
	asset_icp[asset] = num
}

func seach_domain(domain string) {
	time.Sleep(time.Millisecond * 2000)
	str := fmt.Sprintf("domain.suffix=\"%v\"", domain)
	asset, num := info.SearchTotal(str)
	asset_domain[asset] = num
}

func AssetExport(moudle int) {
	switch moudle { // 判断导出模式
	case 0:
		if len(asset_icp) > 0 {
			for icp, total := range asset_icp {
				if icp != "" {
					time.Sleep(time.Millisecond * 2000)
					info.Export(icp, int(total))
				}
			}
		}
	case 1:
		if len(asset_domain) > 0 {
			for domain, total := range asset_domain {
				if domain != "" {
					time.Sleep(time.Millisecond * 2000)
					info.Export(domain, int(total))
				}
			}
		}
	case 2:
		if len(asset_icp) > 0 {
			for icp, total := range asset_icp {
				if icp != "" {
					time.Sleep(time.Millisecond * 2000)
					info.Export(icp, int(total))
				}
			}
		}
		if len(asset_domain) > 0 {
			for domain, total := range asset_domain {
				if domain != "" {
					time.Sleep(time.Millisecond * 2000)
					info.Export(domain, int(total))
				}
			}
		}
	}
}
