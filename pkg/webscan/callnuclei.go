package webscan

import (
	"context"
	"fmt"
	"initial/pkg/color"

	"github.com/projectdiscovery/gologger"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type VulnerabilityInfo struct {
	ID          string
	Name        string
	Description string
	Reference   string
	Type        string
	Risk        string
	URL         string
	Request     string
	Response    string
	Extract     string
}

type NucleiOption struct {
	URL          string
	Tags         []string // 全漏洞扫描时，使用自定义标签
	TemplateFile []string
	Proxy        string
}

var pocFile = "./config/pocs"

func NewNucleiEngine(o NucleiOption, debug bool) {
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
		fmt.Printf("[%s] [%s] %s\n", event.TemplateID, color.WithSeverityColors(event.Info.SeverityHolder.Severity.String()), event.Matched)
		if debug {
			fmt.Printf("\nRequest: \n%s\n", event.Request)
			fmt.Printf("\nResponse: \n%s\n", event.Response)
		}
		// var reference string
		// if event.Info.Reference != nil && !event.Info.Reference.IsEmpty() {
		// 	reference = strings.Join(event.Info.Reference.ToSlice(), ",")
		// }
		// runtime.EventsEmit(ctx, "nucleiResult", VulnerabilityInfo{
		// 	ID:          event.TemplateID,
		// 	Name:        event.Info.Name,
		// 	Description: event.Info.Description,
		// 	Reference:   reference,
		// 	URL:         event.Matched,
		// 	Request:     event.Request,
		// 	Response:    event.Response,
		// 	Extract:     strings.Join(event.ExtractedResults, " | "),
		// 	Type:        event.Type,
		// 	Risk:        event.Info.SeverityHolder.Severity.String(),
		// })
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
