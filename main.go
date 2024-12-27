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
	gologger.Info().Msg("Start formatting the target")
	targets := clients.ParseURL(options.URL, options.File)
	if len(targets) == 0 {
		return
	}
	gologger.Info().Msgf("Completed processing of available targets: %d", len(targets))
	start := time.Now()
	s := webscan.NewFingerScanner(targets, options)
	if s == nil {
		return
	}
	webscan.NewConfig().InitAll("./config/webfinger.yaml", "./config/dir.yaml", "./config/pocs")
	gologger.Info().Msg("Defalt fingerprint scanning started")
	s.NewFingerScan()
	if options.DeepScan {
		s.NewActiveFingerScan(options.RootPath)
	}
	if !options.NoPoc {
		fmt.Println()
		gologger.Info().Msg("Init nuclei engine, vulnerability scan is running ...")
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
				Debug:        options.Debug,
			})
		}
	}
	fmt.Printf("\n[*] 扫描结束,耗时: %s", time.Since(start))
}
