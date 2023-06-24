package info

import (
	"encoding/csv"
	"fmt"
	"initial/burst"
	"initial/common"
	"os"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/olekukonko/tablewriter"
)

var (
	asset_icp    = make(map[string]int64)
	asset_domain = make(map[string]int64)
	vipmsg       string
)

func InitTask(info *common.Info, infoTargets []string) {
	if info.VIP {
		vipmsg = "已开启去重模式,将扣除权益积分"
	} else {
		vipmsg = "未开启去重模式,优先消耗免费积分"
	}
	if info.WhollySubsidiary {
		fmt.Println("\033[36m[+] 正在查询全资子公司以及反查ICP域名备案信息\033[37m")
		for _, t := range infoTargets {
			fuzzname, subsidiaries := SearchSubsidiary(t)
			if t != fuzzname {
				infoTargets = common.ReplaceElement(infoTargets, t, fuzzname) // 将错误的名称替换成正确的ICP(含误报概率)
			}
			infoTargets = append(infoTargets, subsidiaries...)
			time.Sleep(time.Millisecond * 2000)
		}
	}
	if len(infoTargets)+len(TargetDomain) > 0 {
		os.Mkdir("./report", 0664)
		fmt.Printf("\033[36m[+] 正在进行hunter资产数量查询,总数:%d,%s\033[37m\n", len(infoTargets)+len(TargetDomain), vipmsg)
		file, _ := os.OpenFile(fmt.Sprintf("./report/info_%v.csv", time.Now().Format("2006-01-02 15_04_05")), os.O_CREATE|os.O_RDWR, os.ModePerm) // 创建结果文件
		file.WriteString("\xEF\xBB\xBF")
		Result = csv.NewWriter(file)
		bar := pb.StartNew(len(infoTargets) + len(TargetDomain))
		for _, t := range infoTargets {
			bar.Increment()
			seach_icp(t, info.VIP)
		}
		for _, domain := range TargetDomain {
			bar.Increment()
			seach_domain(domain, info.VIP)
		}
		bar.Finish()
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"公司名称OR域名", "HUNTER资产数量"})
		for _, v := range AssetData {
			table.Append(v)
		}
		table.Render() // Send output
		fmt.Printf("\033[36m%v\033[37m\n", Restquota)
	}
	if info.BurstFile != "" {
		var newdomains []string
		for domain := range asset_domain {
			if domain != "" {
				domain = strings.Split(domain, "=\"")[1]
				domain = domain[:len(domain)-1]
				newdomains = append(newdomains, domain)
			}
		}
		b := &common.Burst{
			SubFile: info.BurstFile,
			Thread:  600,
			Level:   1,
			Timeout: 3,
		}
		burst.SubdomainBurst(newdomains, b)
	}
	// 全部导出
	if info.Export {
		ExportMoudle(info.Moudle, asset_icp, asset_domain, info.VIP)
	}
}

func seach_icp(company string, vip bool) {
	time.Sleep(time.Millisecond * 2000)
	str := fmt.Sprintf("icp.name=\"%v\"", company)
	asset, num := SearchTotal(str, vip)
	asset_icp[asset] = num
}

func seach_domain(domain string, vip bool) {
	time.Sleep(time.Millisecond * 2000)
	str := fmt.Sprintf("domain.suffix=\"%v\"", domain)
	asset, num := SearchTotal(str, vip)
	asset_domain[asset] = num
}
