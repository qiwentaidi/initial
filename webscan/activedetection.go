package webscan

import (
	"context"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Knetic/govaluate"
	"gopkg.in/yaml.v3"
)

//go:embed detection/*
var sensitivefile embed.FS

// ActiveDetection 主动探测扫描敏感目录
func ActiveDetection(url string, client *http.Client) (sensitive []string) {
	yamlFile, _ := fs.ReadDir(sensitivefile, "detection")
	for _, file := range yamlFile {
		var matched bool
		var pr PocRule
		data, err := fs.ReadFile(sensitivefile, "detection/"+file.Name())
		if err != nil {
			log.Fatal(err)
		}
		yaml.Unmarshal(data, &pr)
		for _, rule := range pr.Requests { // 遍历请求
			CheckFollowRedirects(rule.FollowRedirects, client)
			for _, uri := range rule.Path {
				cd := GetPocResp(url+uri, rule.Method, rule.Headers, rule.Params, client)
				if matched = MatchPoc(rule.Matchers, cd); matched {
					sensitive = append(sensitive, pr.Name)
				}
			}
		}
	}
	return sensitive
}

// 返回status,body,header
func GetPocResp(url, method string, headers, params map[string]string, client *http.Client) *CheckDatas {
	var checkdatas CheckDatas
	req, err := http.NewRequest(method, url, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if err != nil {
		log.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Add(k, v)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, _ := client.Do(req.WithContext(ctx))
	if r != nil {
		checkdatas.Body, err = io.ReadAll(r.Body)
		if err != nil {
			log.Fatal(err)
		}
		for k, v := range r.Header {
			checkdatas.Headers += fmt.Sprintf("%v:%v", k, v)
		}
		checkdatas.Status = r.StatusCode
	}
	return &checkdatas
}

// 匹配poc内容
func MatchPoc(exp string, checkdatas *CheckDatas) bool {
	// 定义自定义函数
	contains := func(args ...interface{}) (interface{}, error) {
		str := args[0].(string)
		substr := args[1].(string)
		return strings.Contains(str, substr), nil
	}
	// 将自定义函数添加到函数映射中
	functions := map[string]govaluate.ExpressionFunction{
		"contains": contains,
	}
	params := make(map[string]interface{})
	params["status"] = checkdatas.Status
	//params["byte(body)"] = checkdatas.Body
	params["body"] = string(checkdatas.Body)
	params["headers"] = checkdatas.Headers
	// 构造一个包含表达式的 EvaluableExpression 对象，并使用 AddFunctions 函数将函数映射添加到该对象中
	expr, err := govaluate.NewEvaluableExpressionWithFunctions(exp, functions)
	if err != nil {
		log.Fatal(err)
	}
	// 调用 Eval 函数，传入一个 map，其中包含表达式中用到的参数和对应的值
	result, err1 := expr.Evaluate(govaluate.MapParameters(params))
	if err1 != nil {
		log.Fatal(err1)
	}
	return result.(bool)
}
