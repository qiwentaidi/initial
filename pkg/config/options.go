package config

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/urfave/cli/v2"
)

type Options struct {
	Scan
}

type Scan struct {
	URL      string
	File     string
	Thread   int
	Timeout  float64
	DeepScan bool
	RootPath bool
	NoPoc    bool
	Template string
	Proxy    string
	Debug    bool
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
 \:\__\     |:/  /   \:\__\   /:/__/     \:\__\     /:/  /   \:\__\  
  \/__/     \/__/     \/__/   \/__/       \/__/     \/__/     \/__/
	`)
}

func NewOptions() *Options {
	Banner()
	var cf Options
	app := &cli.App{
		Name:      "initial",
		Usage:     "slack cli",
		Version:   "1.0.6",
		UsageText: "initial ws -u http://www.baidu.com",
		Commands: []*cli.Command{
			{
				Name:  "ws",
				Usage: "slack cli for webscan",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "u", Usage: "url"},
					&cli.StringFlag{Name: "f", Usage: "url file"},
					&cli.BoolFlag{Name: "d", Usage: "enable deepScan to check more fingerprints, e.g nacos xxl-job"},
					&cli.BoolFlag{Name: "rp", Value: true, Usage: "does the deep fingerprint adopt root path scanning"},
					&cli.BoolFlag{Name: "nopoc", Value: false, Usage: "don't call nuclei for vulnerability scanning"},
					&cli.StringFlag{Name: "t", Value: "./config/pocs", Usage: "template file or directory"},
					&cli.IntFlag{Name: "thread", Value: 50, Usage: "thread"},
					&cli.Float64Flag{Name: "timeout", Value: 10, Usage: "web timeout"},
					&cli.BoolFlag{Name: "debug", Value: false, Usage: "show request and response data packet"},
					&cli.StringFlag{Name: "proxy", Usage: "set proxy, e.g: http://127.0.0.1:8080 | sock://127.0.0.1"},
				},
				Action: func(c *cli.Context) error {
					cf.Scan.URL = c.String("u")
					cf.Scan.File = c.String("f")
					cf.Scan.DeepScan = c.Bool("d")
					cf.Scan.Thread = c.Int("t")
					cf.Scan.RootPath = c.Bool("rp")
					cf.Scan.NoPoc = c.Bool("nopoc")
					cf.Scan.Timeout = c.Float64("timeout")
					cf.Scan.Proxy = c.String("proxy")
					return nil
				},
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
	return &cf
}
