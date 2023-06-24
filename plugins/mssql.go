package plugins

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/denisenkom/go-mssqldb"
)

func CheckMssqlServer(host, port string, timeout float64) (result string) {
	connString := fmt.Sprintf("server=%s;userid=sa;password=sa;port=%s", host, port)
	db, err := sql.Open("mssql", connString)
	if err != nil {
		result = ""
		return
	}
	defer db.Close()
	// 手动实现 PingContext 的超时机制
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Duration(timeout)*time.Second))
	defer cancel()
	done := make(chan bool)
	go func() {
		if err := db.PingContext(ctx); err != nil {
			//fmt.Printf("err: %v\n", err)
			if strings.Contains(fmt.Sprintf("%v", err), "该登录名来自不受信任的域") || strings.Contains(fmt.Sprintf("%v", err), "unsupported protocol") {
				result = "Mssql"
			}
		} else {
			result = "\330[35mMssql sa:sa 连接成功\330[37m"
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
