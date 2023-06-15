package common

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/urfave/cli/v2"
)

type CmdFlag struct {
	Info struct {
		CompanyName      string
		CompanyFile      string
		BurstFile        string
		Export           bool
		Moudle           int
		WhollySubsidiary bool
	}
	Scan struct {
		Url             string
		UrlFile         string
		Thread          int
		ActiveDetection bool
	}
}

func init() {
	go func() {
		for {
			GC()
			time.Sleep(10 * time.Second)
		}
	}()
}

func GC() {
	runtime.GC()
	debug.FreeOSMemory()
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
		Version:   "1.0.4",
		UsageText: "go run main.go info -u target_url || go run main.go scan -c \"company_name\" -w true",
		Commands: []*cli.Command{
			{
				Name:    "info",
				Aliases: []string{"i"},
				Usage:   "使用信息收集模块,可通过ICP备案名称查询全资子公司以及hunter资产数量,支持子域名暴破",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "b", Value: "", Usage: "指定子域名字典文件,开启子域名暴破功能"},
					&cli.StringFlag{Name: "c", Usage: "需要进行查询的ICP名称"},
					&cli.StringFlag{Name: "f", Usage: "指定需要进行查询ICP名称文件"},
					&cli.IntFlag{Name: "m", Value: 0, Usage: "是否需要导出HUNTER资产文件(开启去重功能),-n数量不为0才会导出\n0 - 仅导出查询ICP资产\n1 - 仅导出域名ICP资产\n2 - ICP资产和域名资产都导出(会有重复资产)"},
					&cli.BoolFlag{Name: "e", Usage: "是否导出HUNTER查询到的全部资产"},
					&cli.BoolFlag{Name: "w", Usage: "进行一级全资子公司查询和ICP备案名反查域名(会自动纠正ICP名称,但是有误报概率)"},
				},
				Action: func(c *cli.Context) error {
					cf.Info.BurstFile = c.String("b")
					cf.Info.CompanyName = c.String("c")
					cf.Info.CompanyFile = c.String("f")
					cf.Info.Export = c.Bool("e")
					cf.Info.Moudle = c.Int("m")
					cf.Info.WhollySubsidiary = c.Bool("w")
					return nil
				},
			},
			{
				Name:    "scan",
				Aliases: []string{"s"},
				Usage:   "使用资产扫描模块,可以用于目标指纹探测,敏感目录探测",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "a", Usage: "是否开启主动探测"},
					&cli.StringFlag{Name: "u", Value: "", Usage: "目标URL"},
					&cli.StringFlag{Name: "f", Usage: "目标URL文件"},
					&cli.IntFlag{Name: "t", Value: 100, Usage: "指定线程数量"},
				},
				Action: func(c *cli.Context) error {
					cf.Scan.Url = c.String("u")
					cf.Scan.UrlFile = c.String("f")
					cf.Scan.Thread = c.Int("t")
					cf.Scan.ActiveDetection = c.Bool("a")
					return nil
				},
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
	return cf
}
