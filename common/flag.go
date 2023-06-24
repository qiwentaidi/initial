package common

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/urfave/cli/v2"
)

type CmdFlag struct {
	Info
	Scan
	Burst
}

type Info struct {
	CompanyName      string
	CompanyFile      string
	BurstFile        string
	Export           bool
	Moudle           int
	WhollySubsidiary bool
	VIP              bool
}

type Scan struct {
	Url             string
	UrlFile         string
	Ip              string
	IpFile          string
	Ports           string
	Thread          int
	Timeout         float64
	ActiveDetection bool
	Proxy           string
	Auth            string
}

type Burst struct {
	Domain     string
	DomainFile string
	SubFile    string
	Level      int
	Thread     int
	Timeout    float64
}

func init() {
	go func() {
		for {
			runtime.GC()
			debug.FreeOSMemory()
			time.Sleep(10 * time.Second)
		}
	}()
}

func Banner() {
	fmt.Println(`
   ___       ___       ___       ___       ___       ___       ___   
  /\  \     /\__\     /\  \     /\  \     /\  \     /\  \     /\__\  
 _\:\  \   /:| _|_   _\:\  \    \:\  \   _\:\  \   /::\  \   /:/  /  
/\/::\__\ /::|/\__\ /\/::\__\   /::\__\ /\/::\__\ /::\:\__\ /:/__/   
\::/\/__/ \/|::/  / \::/\/__/  /:/\/__/ \::/\/__/ \/\::/  / \:\  \   
 \:\__\     |:/  /   \:\__\    \/__/     \:\__\     /:/  /   \:\__\  
  \/__/     \/__/     \/__/               \/__/     \/__/     \/__/
	`)
}

func Flag() CmdFlag {
	Banner()
	var cf CmdFlag
	app := &cli.App{
		Name:      "initial",
		Usage:     "一切归于起点",
		Version:   "1.0.5",
		UsageText: "go run main.go info -u http://www.baidu.com\ngo run main.go scan -c 北京百度网讯科技有限公司 -w\ngo run main.go burst -d baidu.com -sf dic.txt",
		Commands: []*cli.Command{
			{
				Name:  "info",
				Usage: "使用信息收集模块,可通过ICP备案名称查询全资子公司以及hunter资产数量,支持子域名暴破",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "c", Usage: "需要进行查询的ICP名称"},
					&cli.StringFlag{Name: "f", Usage: "指定需要进行查询ICP名称文件"},
					&cli.BoolFlag{Name: "w", Usage: "进行一级全资子公司查询和ICP备案名反查域名(会自动纠正ICP名称,但是有误报概率)"},
					&cli.StringFlag{Name: "b", Value: "", Usage: "指定子域名字典文件,开启子域名暴破功能"},
					&cli.IntFlag{Name: "m", Value: 0, Usage: "是否需要导出HUNTER资产文件\n0 - 仅导出查询ICP资产\n1 - 仅导出反查到的域名资产\n2 - ICP资产和域名资产都导出(会有重复资产)"},
					&cli.BoolFlag{Name: "e", Usage: "是否导出HUNTER查询到的全部资产"},
					&cli.BoolFlag{Name: "vip", Usage: "是否进行资产去重(该功能消耗权益积分)"},
				},
				Action: func(c *cli.Context) error {
					cf.Info.BurstFile = c.String("b")
					cf.Info.CompanyName = c.String("c")
					cf.Info.CompanyFile = c.String("f")
					cf.Info.Export = c.Bool("e")
					cf.Info.Moudle = c.Int("m")
					cf.Info.WhollySubsidiary = c.Bool("w")
					cf.Info.VIP = c.Bool("vip")
					return nil
				},
			},
			{
				Name:  "scan",
				Usage: "使用资产扫描模块,可以用于网站指纹探测,敏感目录探测,IP端口扫描,端口指纹识别",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "a", Usage: "开启主动探测"},
					&cli.StringFlag{Name: "u", Usage: "URL"},
					&cli.StringFlag{Name: "uf", Usage: "URL文件"},
					&cli.StringFlag{Name: "ip", Usage: "IP地址,例如: 192.168.11.11 | 192.168.11.0-192.168.11.254 | 192.168.11.11,192.168.11.12"},
					&cli.StringFlag{Name: "p", Value: Serverport + "," + Webport, Usage: "需要扫描的端口,例如: 22 | 1-65535 | 22,80,3306"},
					&cli.StringFlag{Name: "hf", Usage: "IP文件"},
					&cli.IntFlag{Name: "t", Value: 100, Usage: "线程数量"},
					&cli.Float64Flag{Name: "timeout", Value: 3, Usage: "设置端口&URL超时"},
					&cli.StringFlag{Name: "proxy", Usage: "设置代理,例如: http://127.0.0.1:8080 | sock://127.0.0.1"},
					&cli.StringFlag{Name: "auth", Usage: "设置sock代理认证, username:password"},
				},
				Action: func(c *cli.Context) error {
					cf.Scan.Url = c.String("u")
					cf.Scan.UrlFile = c.String("uf")
					cf.Scan.ActiveDetection = c.Bool("a")
					cf.Scan.Ip = c.String("ip")
					cf.Scan.IpFile = c.String("hf")
					cf.Scan.Ports = c.String("p")
					cf.Scan.Thread = c.Int("t")
					cf.Scan.Timeout = c.Float64("timeout")
					cf.Scan.Proxy = c.String("proxy")
					cf.Scan.Auth = c.String("auth")
					return nil
				},
			},
			{
				Name:  "burst",
				Usage: "使用暴破模块,可以用于子域名暴破",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "d", Usage: "域名"},
					&cli.StringFlag{Name: "df", Usage: "域名文件"},
					&cli.StringFlag{Name: "sf", Usage: "子域字典文件"},
					&cli.IntFlag{Name: "t", Value: 600, Usage: "线程数量,默认情况跑16w的字典大概4分钟"},
					&cli.IntFlag{Name: "l", Value: 1, Usage: "多级子域暴破"},
					&cli.IntFlag{Name: "timeout", Value: 3, Usage: "解析到域名后的URL超时"},
				},
				Action: func(c *cli.Context) error {
					cf.Burst.Domain = c.String("d")
					cf.Burst.DomainFile = c.String("df")
					cf.Burst.SubFile = c.String("sf")
					cf.Burst.Thread = c.Int("t")
					cf.Burst.Level = c.Int("l")
					cf.Burst.Timeout = c.Float64("timeout")
					return nil
				},
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
	return cf
}
