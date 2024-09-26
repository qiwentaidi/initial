package main

import (
	"fmt"
	"initial/pkg/clients"
	"initial/pkg/config"
	"initial/pkg/utils"
	"initial/pkg/webscan"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
)

func main() {
	options := config.NewOptions()
	if options.URL == "" && options.File == "" {
		gologger.Error().Msg("No available targets found, please input target or file")
		return
	}
	// 整理目标
	targets := utils.ParseURL(options.Scan.URL, options.Scan.File)
	start := time.Now()
	s := webscan.NewFingerScanner(targets, clients.Proxy{}, options)
	if s == nil {
		return
	}
	webscan.NewConfig().InitAll("./config/webfinger.yaml", "./config/dir.yaml", "./config/pocs")
	fmt.Println("[*] Defalt fingerprint scanning started")
	s.NewFingerScan()
	if options.DeepScan {
		s.NewActiveFingerScan(options.RootPath)
	}
	if !options.NoPoc {
		fmt.Println("\n[*] Performing vulnerability scanning")
		var id = 0
		var templates []string
		fpm := s.URLWithFingerprintMap()
		count := len(fpm)
		for target, tags := range fpm {
			id++
			gologger.Info().Msg(fmt.Sprintf("正在扫描第%d/%d个目标", id, count))
			if options.Template != "" {
				templates = strings.Split(options.Template, ",")
			}
			webscan.NewNucleiEngine(webscan.NucleiOption{
				URL:          target,
				Tags:         utils.RemoveDuplicates(tags),
				TemplateFile: templates,
				Proxy:        options.Proxy,
			}, options.Debug)
		}
	}
	fmt.Printf("\n[*] 扫描结束,耗时: %s", time.Since(start))
}
