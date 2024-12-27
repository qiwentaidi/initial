package waf

import (
	"initial/pkg/netutil"
	"regexp"
	"strings"
)

var (
	WAFs = map[string][]string{
		"sanfor-shield":       {".sangfordns.com"},
		"360panyun":           {".360panyun.com"},
		"baiduyun":            {".yunjiasu-cdn.net"},
		"chuangyudun":         {".365cyd.cn", ".cyudun.net", ".365cyd.net"},
		"knownsec":            {".jiashule.com", ".jiasule.org"},
		"huaweicloud":         {".huaweicloudwaf.com"},
		"xinliuyun":           {".ngaagslb.cn"},
		"chinacache":          {".chinacache.net", ".ccgslb.net", ".chinacache.com"},
		"nscloudwaf":          {".nscloudwaf.com"},
		"wangsu":              {".wsssec.com", ".lxdns.com", ".wscdns.com", ".cdn20.com", ".cdn30.com", ".ourplat.net", ".wsdvs.com", ".wsglb0.com", ".wswebcdn.com", ".wswebpic.com", ".wsssec.com", ".wscloudcdn.com", ".mwcloudcdn.com", ".chinanetcenter.com"},
		"qianxin":             {".360safedns.com", ".360cloudwaf.com", ".360wzb.com", ".qaxcloudwaf.com"},
		"baiduyunjiasu":       {".yunjiasu-cdn.net"},
		"anquanbao":           {".anquanbao.net", ".anquanbao.com"},
		"aliyun":              {"kunlun", "aliyunddos", "aliyunwaf", "aligaofang", "aliyundunwaf", ".yundunwaf2.com", ".yundunwaf1.com"},
		"xuanwudun":           {".saaswaf.com", ".dbappwaf.cn"},
		"yundun":              {".hwwsdns.cn", ".yunduncname.com"},
		"knownsec-ns":         {".jiasule.net"},
		"baiduyunjiasue":      {".ns.yunjiasu.com"},
		"cloudflare":          {".ns.cloudflare.com"},
		"edns":                {".iidns.com"},
		"ksyun":               {".ksyunwaf.com"},
		"jdcloud-star-shield": {".cloud-scdn.com"},
	}
	RegIP             = regexp.MustCompile(`((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}`)
	DefaultDnsServers = []string{"223.6.6.6:53", "8.8.8.8:53"}
)

type WAF struct {
	Exsits bool
	Name   string
}

// waf 识别
func ResolveAndWafIdentify(host string, dnsServers []string) *WAF {
	// 如果是IP则直接返回
	if RegIP.MatchString(host) {
		return &WAF{}
	}
	cnames, err := netutil.LookupCNAME(host, dnsServers, 3)
	if err != nil || len(cnames) == 0 {
		return &WAF{}
	}
	for name, domains := range WAFs {
		for _, domain := range domains {
			if strings.Contains(cnames[0], domain) {
				return &WAF{Exsits: true, Name: name}
			}
		}
	}
	return &WAF{}
}

func CheckWAF(cnames []string) *WAF {
	if len(cnames) == 0 {
		return &WAF{}
	}
	for name, domains := range WAFs {
		for _, domain := range domains {
			if strings.Contains(cnames[0], domain) {
				return &WAF{Exsits: true, Name: name}
			}
		}
	}
	return &WAF{}
}
