package info

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type HunterResult struct {
	Code int64 `json:"code"`
	Data struct {
		AccountType string `json:"account_type"`
		Arr         []struct {
			AsOrg        string `json:"as_org"`
			Banner       string `json:"banner"`
			BaseProtocol string `json:"base_protocol"`
			City         string `json:"city"`
			Company      string `json:"company"`
			Component    []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"component"`
			Country        string `json:"country"`
			Domain         string `json:"domain"`
			IP             string `json:"ip"`
			IsRisk         string `json:"is_risk"`
			IsRiskProtocol string `json:"is_risk_protocol"`
			IsWeb          string `json:"is_web"`
			Isp            string `json:"isp"`
			Number         string `json:"number"`
			Os             string `json:"os"`
			Port           int64  `json:"port"`
			Protocol       string `json:"protocol"`
			Province       string `json:"province"`
			StatusCode     int64  `json:"status_code"`
			UpdatedAt      string `json:"updated_at"`
			URL            string `json:"url"`
			WebTitle       string `json:"web_title"`
		} `json:"arr"`
		ConsumeQuota string `json:"consume_quota"`
		RestQuota    string `json:"rest_quota"`
		SyntaxPrompt string `json:"syntax_prompt"`
		Time         int64  `json:"time"`
		Total        int64  `json:"total"`
	} `json:"data"`
	Message string `json:"message"`
}

type Config struct {
	HunterAPI string `json:"hunter-api"`
}

var (
	hunterkey     string
	Restquota     string
	Result        *csv.Writer
	AssetData     [][]string
	deduplication string
)

func init() {
	// 判断文件是否存在
	_, err := os.Stat("config.json")
	if os.IsNotExist(err) {
		// 文件不存在，创建并写入内容
		config := Config{
			HunterAPI: "",
		}
		data, err := json.MarshalIndent(config, "", "    ")
		if err != nil {
			log.Fatal(err)
		}
		err = os.WriteFile("config.json", data, 0644)
		if err != nil {
			log.Fatal(err)
		}
	}
	data, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatal(err)
	}
	// 解码 JSON 数据
	var config Config
	json.Unmarshal(data, &config)
	if config.HunterAPI == "" {
		log.Fatal("hunter-api未配置,请在config.json文件中配置。")
		return
	} else {
		hunterkey = config.HunterAPI
	}
}

func SearchTotal(search string, vip bool) (asset string, num int64) {
	if vip {
		deduplication = "true"
	} else {
		deduplication = "false"
	}
	current_time := time.Now()
	before_time := current_time.AddDate(0, -1, 0)
	addr := "https://hunter.qianxin.com/openApi/search?api-key=" + hunterkey + "&search=" + hunterBaseEncode(search) + "&page=1&page_size=1&is_web=3&port_filter=" + deduplication + "&start_time=" + before_time.Format("2006-01-02") + "&end_time=" + current_time.Format("2006-01-02")
	r, err := http.Get(addr)
	if err != nil {
		log.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	defer r.Body.Close()
	var hr HunterResult
	json.Unmarshal([]byte(string(b)), &hr)
	if hr.Code != 200 {
		fmt.Println(hr)
	} else {
		AssetData = append(AssetData, []string{strings.Split(search, "\"")[1], fmt.Sprintf("%v", hr.Data.Total)})
		Result.Write([]string{strings.Split(search, "\"")[1], fmt.Sprintf("%v", hr.Data.Total)})
		Result.Flush()
		if hr.Data.Total > 0 {
			asset = search
		}
	}
	Restquota = hr.Data.RestQuota
	return asset, hr.Data.Total // 返回需要后查询导出的资产名称
}

// hunter base64加密接口
func hunterBaseEncode(str string) string {
	s := base64.URLEncoding.EncodeToString([]byte(str))
	if s[len(s)-1:] == "=" && s[len(s)-2:] != "==" {
		s = s[:len(s)-1]
	}
	return s
}

func ExportMoudle(moudle int, asset_icp, asset_domain map[string]int64, vip bool) {
	if vip {
		deduplication = "true"
	} else {
		deduplication = "false"
	}
	fmt.Printf("需要导出查询的ICP名称共:	\033[35m%d个\033[37m,需要导出查询的查询的域名共:	\033[35m%d个\033[37m\n", len(asset_icp), len(asset_domain))
	switch moudle {
	case 0:
		fmt.Println("[!]当前导出模式为-仅导出ICP资产")
	case 1:
		fmt.Println("[!]当前导出模式为-仅导出域名资产")
	case 2:
		fmt.Println("[!]当前导出模式为-导出ICP和域名资产")
	default:
		panic("导出模式错误")
	}
	switch moudle { // 判断导出模式
	case 0:
		if len(asset_icp) > 0 {
			for icp, total := range asset_icp {
				if icp != "" {
					time.Sleep(time.Millisecond * 2000)
					AssetExport(icp, int(total), deduplication)
				}
			}
		}
	case 1:
		if len(asset_domain) > 0 {
			for domain, total := range asset_domain {
				if domain != "" {
					time.Sleep(time.Millisecond * 2000)
					AssetExport(domain, int(total), deduplication)
				}
			}
		}
	case 2:
		if len(asset_icp) > 0 {
			for icp, total := range asset_icp {
				if icp != "" {
					time.Sleep(time.Millisecond * 2000)
					AssetExport(icp, int(total), deduplication)
				}
			}
		}
		if len(asset_domain) > 0 {
			for domain, total := range asset_domain {
				if domain != "" {
					time.Sleep(time.Millisecond * 2000)
					AssetExport(domain, int(total), deduplication)
				}
			}
		}
	}
}

func AssetExport(search string, total int, deduplication string) {
	var addr string
	file, _ := os.OpenFile(fmt.Sprintf("./report/asset_%v.csv", time.Now().Format("2006-01-02 15_04_05")), os.O_CREATE|os.O_RDWR, os.ModePerm) // 创建结果文件
	file.WriteString("\xEF\xBB\xBF")
	assetFile := csv.NewWriter(file)
	current_time := time.Now()
	before_time := current_time.AddDate(0, -1, 0)
	if total <= 100 && total > 0 {
		addr = "https://hunter.qianxin.com/openApi/search?api-key=" + hunterkey + "&search=" + hunterBaseEncode(search) + "&page=1&page_size=100&is_web=3&port_filter=" + deduplication + "&start_time=" + before_time.Format("2006-01-02") + "&end_time=" + current_time.Format("2006-01-02")
		r, err := http.Get(addr)
		if err != nil {
			panic(err)
		}
		b, _ := io.ReadAll(r.Body)
		defer r.Body.Close()
		var hr HunterResult
		json.Unmarshal([]byte(string(b)), &hr)
		if hr.Code != 200 {
			fmt.Println(hr)
		} else {
			for _, arr := range hr.Data.Arr {
				assetFile.Write([]string{arr.Company, arr.Domain, arr.IP, fmt.Sprintf("%v", arr.Port), arr.Protocol, arr.URL, arr.WebTitle})
				assetFile.Flush()
			}
		}
	} else if total > 100 {
		var count int
		if total%100 == 0 {
			count = total / 100
		} else {
			count = total/100 + 1
		}
		for i := 1; i <= count; i++ {
			addr = "https://hunter.qianxin.com/openApi/search?api-key=" + hunterkey + "&search=" + hunterBaseEncode(search) + "&page=" + fmt.Sprintf("%v", i) + "&page_size=100&is_web=3&port_filter=true&start_time=" + before_time.Format("2006-01-02") + "&end_time=" + current_time.Format("2006-01-02")
			r, err := http.Get(addr)
			if err != nil {
				panic(err)
			}
			b, _ := io.ReadAll(r.Body)
			defer r.Body.Close()
			var hr HunterResult
			json.Unmarshal([]byte(string(b)), &hr)
			if hr.Code != 200 {
				fmt.Println(hr)
			} else {
				for _, arr := range hr.Data.Arr {
					assetFile.Write([]string{arr.Company, arr.Domain, arr.IP, fmt.Sprintf("%v", arr.Port), arr.Protocol, arr.URL, arr.WebTitle})
					assetFile.Flush()
				}
			}
			time.Sleep(time.Millisecond * 2000)
		}
	}
	fmt.Printf("[*] 导出结束,共计扣除积分%v...", total)
}
