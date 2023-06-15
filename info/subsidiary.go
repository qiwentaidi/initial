package info

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

var TargetDomain = []string{} //待检测资产数量的icp域名目标

type QccSearchID struct {
	State      string `json:"state"`
	Message    string `json:"message"`
	Special    string `json:"special"`
	VipMessage string `json:"vipMessage"`
	IsLogin    int    `json:"isLogin"`
	ErrorCode  int    `json:"errorCode"`
	Data       []struct {
		ID         int         `json:"id"`
		GraphID    string      `json:"graphId"`
		Type       int         `json:"type"`
		MatchType  string      `json:"matchType"`
		ComName    string      `json:"comName"`
		Name       string      `json:"name"`
		Alias      string      `json:"alias"`
		Logo       string      `json:"logo"`
		ClaimLevel interface{} `json:"claimLevel"`
		RegStatus  int         `json:"regStatus"`
	} `json:"data"`
}

type QccResult struct {
	State      string `json:"state"`
	Message    string `json:"message"`
	Special    string `json:"special"`
	VipMessage string `json:"vipMessage"`
	IsLogin    int    `json:"isLogin"`
	ErrorCode  int    `json:"errorCode"`
	Data       struct {
		Result []struct {
			Name             string      `json:"name"` // 公司名称
			PersonType       int         `json:"personType"`
			ServiceType      interface{} `json:"serviceType"`
			RegStatus        string      `json:"regStatus"`
			Percent          string      `json:"percent"` // 股权比例
			LegalPersonTitle string      `json:"legalPersonTitle"`
			LegalPersonName  string      `json:"legalPersonName"`
			Logo             interface{} `json:"logo"`
			Alias            string      `json:"alias"`
			ID               int64       `json:"id"`
			Amount           string      `json:"amount"`
			EstiblishTime    int64       `json:"estiblishTime"`
			LegalPersonID    int         `json:"legalPersonId"`
			ServiceCount     interface{} `json:"serviceCount"`
			LegalAlias       interface{} `json:"legalAlias"`
			LegalLogo        interface{} `json:"legalLogo"`
			JigouName        interface{} `json:"jigouName"`
			JigouLogo        interface{} `json:"jigouLogo"`
			JigouID          interface{} `json:"jigouId"`
			ProductName      interface{} `json:"productName"`
			ProductLogo      interface{} `json:"productLogo"`
			ProductID        interface{} `json:"productId"`
		} `json:"result"`
		SortField   interface{} `json:"sortField"`
		PercentList []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"percentList"`
		ProvinceList []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"provinceList"`
		CategoryList []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"categoryList"`
		Total int `json:"total"`
	} `json:"data"`
}

var (
	max          int
	id           int
	company_name string
	company_id   string
	cyan         = color.New(color.FgHiCyan)
)

func companyid(company string) (string, string) {
	data := make(map[string]interface{})
	data["keyword"] = company
	bytesData, _ := json.Marshal(data)
	client := &http.Client{}
	r, err := http.NewRequest("POST", "https://capi.tianyancha.com/cloud-tempest/search/suggest/v3", bytes.NewReader(bytesData))
	r.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36")
	r.Header.Add("Content-Type", "application/json")
	if err != nil {
		log.Fatal(err)
	}
	r2, err2 := client.Do(r)
	if err2 != nil {
		log.Fatal(err2)
	}
	b, err3 := io.ReadAll(r2.Body)
	if err3 != nil {
		log.Fatal(err3)
	}
	var qs QccSearchID
	json.Unmarshal([]byte(string(b)), &qs)
	if len(qs.Data) > 0 { // 先走接口不会进行模糊匹配,如果匹配不到值那就走模糊查询
		return qs.Data[0].GraphID, qs.Data[0].ComName
	} else {
		r, err = http.NewRequest("GET", "https://www.tianyancha.com/search?key="+url.QueryEscape(company), nil)
		if err != nil {
			log.Fatal(err)
		}
		r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36")
		r2, _ = client.Do(r)
		b, err1 := io.ReadAll(r2.Body)
		if err1 != nil {
			log.Fatal(err1)
		}
		fuzzy := regexp.MustCompile(`\d{10}" target="_blank">(.*?)</span></a>`)
		all := fuzzy.FindAllString(string(b), -1)
		for _, v := range all {
			s := strings.Split(v, `" target="_blank"><span>`)
			f := s[1][:len(s[1])-11] // 模糊匹配到的词绍兴市<em>公安</em>局<em>越城</em>区<em>分局</em>
			id = 0
			var temp string
			for _, keyword := range strings.Split(strings.ReplaceAll(f, "/", ""), "<em>") {
				if strings.Contains(company, keyword) {
					id++
				}
				temp += keyword
			}
			if max < id {
				max = id
				company_id = s[0]
				company_name = temp
			}
		}
		return company_id, company_name
	}
}

func SearchSubsidiary(company string) (fuzzname string, subsidiaries []string) {
	var holdData [][]string
	data := make(map[string]interface{})
	data["gid"], fuzzname = companyid(company)
	data["pageSize"] = 100
	data["pageNum"] = 1
	data["province"] = "-100"
	data["percentLevel"] = "-100"
	data["category"] = "-100"
	bytesData, _ := json.Marshal(data)
	client := &http.Client{}
	r, err := http.NewRequest("POST", "https://capi.tianyancha.com/cloud-company-background/company/investListV2", bytes.NewReader(bytesData))
	r.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36")
	r.Header.Add("Content-Type", "application/json")
	if err != nil {
		log.Fatal(err)
	}
	r2, err2 := client.Do(r)
	if err2 != nil {
		log.Fatal(err2)
	}
	b, err3 := io.ReadAll(r2.Body)
	if err3 != nil {
		log.Fatal(err3)
	}
	var qr QccResult
	json.Unmarshal([]byte(string(b)), &qr)
	if company != fuzzname {
		cyan.Printf("[!] %v——天眼查模糊匹配名称为——%v,正在以新名称替换查询目标...\n", company, fuzzname)
		_, domains := Icp2Domain(fuzzname)
		TargetDomain = append(TargetDomain, domains...)
		holdData = append(holdData, []string{fuzzname + "(" + company + ")", "母公司", list2string(domains)})
	} else {
		_, domains := Icp2Domain(fuzzname)
		TargetDomain = append(TargetDomain, domains...)
		holdData = append(holdData, []string{fuzzname, "本公司", list2string(domains)})
	}
	for _, result := range qr.Data.Result {
		if result.Percent == "100%" {
			num, domains := Icp2Domain(result.Name)
			if num > 0 {
				holdData = append(holdData, []string{result.Name, result.Percent, list2string(domains)})
				TargetDomain = append(TargetDomain, domains...)
			} else {
				holdData = append(holdData, []string{result.Name, result.Percent, ""})
			}
			subsidiaries = append(subsidiaries, result.Name)
		}
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"公司名称", "股权比例", "域名"})
	for _, v := range holdData {
		table.Append(v)
	}
	table.Render()                // Send output
	return fuzzname, subsidiaries // 返回查询公司的名称和子公司的名称
}

func list2string(str []string) (result string) {
	num := len(str)
	for i, v := range str {
		if i+1 != num {
			result += v + ","
		} else {
			result += v
		}
	}
	return result
}
