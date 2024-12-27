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

const version = "1.0.7"

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
		Usage:     "slack cli for webscan",
		Version:   version,
		UsageText: "initial -u http://www.baidu.com",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "u", Usage: "url"},
			&cli.StringFlag{Name: "f", Usage: "url file"},
			&cli.BoolFlag{Name: "d", Value: true, Usage: "enable deepScan to check more fingerprints, e.g nacos xxl-job"},
			&cli.BoolFlag{Name: "rp", Value: true, Usage: "does the deep fingerprint adopt root path scanning"},
			&cli.BoolFlag{Name: "nopoc", Value: false, Usage: "don't call nuclei for vulnerability scanning"},
			&cli.StringFlag{Name: "t", Value: "./config/pocs", Usage: "template file or directory"},
			&cli.IntFlag{Name: "thread", Value: 50, Usage: "fingerscan thread"},
			&cli.Float64Flag{Name: "timeout", Value: 10, Usage: "web timeout"},
			&cli.BoolFlag{Name: "debug", Value: false, Usage: "show request and response data packet"},
			&cli.StringFlag{Name: "proxy", Usage: "set proxy, e.g: http://127.0.0.1:8080 | sock://127.0.0.1"},
		},
		Action: func(c *cli.Context) error {
			cf.URL = c.String("u")
			cf.File = c.String("f")
			cf.DeepScan = c.Bool("d")
			cf.Thread = c.Int("t")
			cf.RootPath = c.Bool("rp")
			cf.NoPoc = c.Bool("nopoc")
			cf.Timeout = c.Float64("timeout")
			cf.Proxy = c.String("proxy")
			return nil
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
	return &cf
}
