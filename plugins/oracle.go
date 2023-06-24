package plugins

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/sijms/go-ora/v2"
)

func CheckOracleServer(host, port string, timeout float64) (result string) {
	connString := fmt.Sprintf("oracle://%s:%s@%s:%s/orcl", "root", "123456", host, port)
	db, err := sql.Open("oracle", connString)
	if err != nil {
		result = fmt.Sprintf("%v", err)
		return
	}
	defer db.Close()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Duration(timeout)*time.Second)) // 手动实现 PingContext 的超时机制
	defer cancel()
	done := make(chan bool)
	go func() {
		if err := db.PingContext(ctx); err != nil {
			if strings.Contains(fmt.Sprintf("%v", err), "ORA") {
				result = "Oracle"
			} else {
				result = ""
			}
		} else {
			result = "\330[35mOracle root:123456 连接成功\330[37m"
		}
		done <- true
	}()
	select {
	case <-done:
		// 处理 PingContext 结果
	case <-ctx.Done():
		// ctx 超时，手动断开连接
		db.Close()
		result = ""
	}
	return result
}
