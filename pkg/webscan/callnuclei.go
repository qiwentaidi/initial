package webscan

import (
	"context"
	"fmt"
	"initial/pkg/color"
	"strings"

	"github.com/projectdiscovery/gologger"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type NucleiOption struct {
	URL          string
	Tags         []string // 全漏洞扫描时，使用自定义标签
	TemplateFile []string
	Proxy        string
	Debug        bool
}

var pocFile = "./config/pocs"

func NewNucleiEngine(o NucleiOption) {
	options := []nuclei.NucleiSDKOptions{
		nuclei.EnableStatsWithOpts(nuclei.StatsOptions{MetricServerPort: 6064}), // optionally enable metrics server for better observability
		nuclei.DisableUpdateCheck(), // -duc
	}
	// 判断是使用指定poc文件还是根据标签
	if len(o.TemplateFile) == 0 {
		options = append(options, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{pocFile},
		}))
		options = append(options, nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			Tags: o.Tags,
		}))
	} else {
		// 指定poc文件的时候就要删除tags标签
		options = append(options, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: o.TemplateFile,
		}))
	}
	if o.Proxy != "" {
		options = append(options, nuclei.WithProxy([]string{o.Proxy}, false)) // -proxy
	}
	ne, err := nuclei.NewNucleiEngineCtx(context.Background(), options...)
	if err != nil {
		gologger.Error().Msg(fmt.Sprintf("nuclei init engine err: %v", err))
		return
	}
	// load targets and optionally probe non http/https targets
	ne.LoadTargets([]string{o.URL}, false)
	err = ne.ExecuteWithCallback(func(event *output.ResultEvent) {
		severity := strings.ToUpper(event.Info.SeverityHolder.Severity.String())
		fmt.Printf("[%s] [%s] %s %s\n", color.LogColor.Vulner(event.TemplateID), color.LogColor.GetColor(event.Info.SeverityHolder.Severity.String(), severity),
			showMatched(event), strings.Join(event.ExtractedResults, " | "))
		if o.Debug {
			fmt.Printf("\nRequest: \n%s\n", showRequest(event))
			fmt.Printf("\nResponse: \n%s\n", showResponse(event))
		}
	})

	if err != nil {
		gologger.Error().Msg(fmt.Sprintf("%s nuclei execute callback err: %v", o.URL, err))
		return
	}
	defer ne.Close()
}

// func Rename(filename string) string {
// 	filename = strings.ReplaceAll(filename, ":", "_")
// 	filename = strings.ReplaceAll(filename, "/", "_")
// 	filename = strings.ReplaceAll(filename, "___", "_")
// 	return filename
// }

func showMatched(event *output.ResultEvent) string {
	if event.Matched != "" {
		return event.Matched
	}
	return event.URL
}

func showRequest(event *output.ResultEvent) string {
	if event.Request != "" {
		return event.Request
	}
	if event.Interaction != nil {
		return event.Interaction.RawRequest
	}
	return ""
}

func showResponse(event *output.ResultEvent) string {
	if event.Response != "" {
		byteResponse := []byte(event.Response)
		if len(byteResponse) > 1024*512 {
			return string(byteResponse[:1024*512]) + " ..."
		}
		return event.Response
	}
	if event.Interaction != nil {
		return event.Interaction.RawResponse
	}
	return ""
}
