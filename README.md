# 使用说明

该项目已停止更新，功能都包含在https://github.com/qiwentaidi/Slack，需要的师父请移步



首先运行`go run .\main.go -h`会在当前目录下生成一个`config.json`的文件，在其中配置正确的`hunter-api`即可使用。

![image-20230524234259910](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230524234259910.png)

`go run main.go -h`，功能主要分布在子命令`is、ws、bs`中

![image-20230705093418645](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230705093418645.png)

## `is`

```
PS E:\Code\Golang\src\hunter_icp> go run .\main.go info -h

   ___       ___       ___       ___       ___       ___       ___
  /\  \     /\__\     /\  \     /\  \     /\  \     /\  \     /\__\
 _\:\  \   /:| _|_   _\:\  \    \:\  \   _\:\  \   /::\  \   /:/  /
/\/::\__\ /::|/\__\ /\/::\__\   /::\__\ /\/::\__\ /::\:\__\ /:/__/
\::/\/__/ \/|::/  / \::/\/__/  /:/\/__/ \::/\/__/ \/\::/  / \:\  \
 \:\__\     |:/  /   \:\__\    \/__/     \:\__\     /:/  /   \:\__\
  \/__/     \/__/     \/__/               \/__/     \/__/     \/__/

NAME:
   initial info - 使用信息收集模块,可通过ICP备案名称查询全资子公司以及hunter资产数量,支持子域名暴破

USAGE:
   initial info [command options] [arguments...]

OPTIONS:
   -c value    需要进行查询的ICP名称
   -f value    指定需要进行查询ICP名称文件
   -w          进行一级全资子公司查询和ICP备案名反查域名(会自动纠正ICP名称,但是有误报概率) (default: false)
   -e          是否导出HUNTER查询到的全部资产 (default: false)
   --em value  是否需要导出HUNTER资产文件
      0 - 仅导出查询ICP资产
      1 - 仅导出反查到的域名资产
      2 - ICP资产和域名资产都导出(会有重复资产) (default: 0)
   --dd        进行资产去重(该功能消耗权益积分) (default: false)
   --st        查询域名与备案名称在HUNTER中的资产数量 (default: false)
   --help, -h  show help
```

| **初衷：** | **为大型活动`hvv`进行信息收集以及资产甄别（快速找出资产多的软柿子）** |
| ---------- | ------------------------------------------------------------ |
| **提示：** | **在查询`hunter api`接口时，每次只会查询1条记录，查询一家单位备案仅消耗1积分，1个域名也是1积分，所以可以不必担心浪费大量积分的情况，由于`hunter api`查询速度限制，每次查询延时2秒，开启VIP功能消耗权益积分在查询数量以及导出资产的时候都会沿用。** |
| **注意：** | **由于`ICP`查域名爬的`https://beian.tianyancha.com/`非工信部网站，所以会出现域名反查遗漏的现象。** |

### 全资子公司查询+反查域名

`-w`参数开启子公司查询模式，子域名资产信息以及名称纠正功能来自天眼查，如果查偏了，请自行纠正备案名称重新查询`-st`查询`HUNTER`资产数量`-dd`表示开启`HUNTER`去重功能。

![image-20230705093600708](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230705093600708.png)

![image-20230705093710235](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230705093710235.png)

### 联动子域名暴破

现在输出效果已经改成`burst`模块输出的样式

`-b`参数指定子域字典目录后，会对反查到的域名进行子域名暴破，可过泛解析，解析超过3次的IP会被拉入黑名单。

![image-20230615091957046](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230615091957046.png)

### `HUNTER`结果导出

`-e`导出资产，`-m`设置导出模式

`go run .\main.go info -c "浙江红狮水泥股份有限公司" -m 0 -e`，结果输出再`/report/assetxxx.csv`

![image-20230615160915739](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230615160915739.png)

## `ws`

```
PS E:\Code\Golang\src\initial> go run .\main.go scan -h

   ___       ___       ___       ___       ___       ___       ___
  /\  \     /\__\     /\  \     /\  \     /\  \     /\  \     /\__\
 _\:\  \   /:| _|_   _\:\  \    \:\  \   _\:\  \   /::\  \   /:/  /
/\/::\__\ /::|/\__\ /\/::\__\   /::\__\ /\/::\__\ /::\:\__\ /:/__/
\::/\/__/ \/|::/  / \::/\/__/  /:/\/__/ \::/\/__/ \/\::/  / \:\  \
 \:\__\     |:/  /   \:\__\    \/__/     \:\__\     /:/  /   \:\__\
  \/__/     \/__/     \/__/               \/__/     \/__/     \/__/

NAME:
   initial scan - 使用资产扫描模块,可以用于网站指纹探测,敏感目录探测,IP端口扫描,端口指纹识别

USAGE:
   initial scan [command options] [arguments...]

OPTIONS:
   -a               开启主动探测 (default: false)
   -u value         URL
   --uf value       URL文件
   --ip value       IP地址,例如: 192.168.11.11 | 192.168.11.0-192.168.11.254 | 192.168.11.11,192.168.11.12
   -p value         需要扫描的端口,例如: 22 | 1-65535 | 22,80,3306 (default: "21,22,80,81,135,139,443,445,1433,1521,3306,3389,5432,6379,7001,8000,8080,8089,9000,9200,11211,27017,80,81,82,83,84,85,86,87,88,89,90,91,92,98,99,443,800,801,808,880,888,889,1000,1010,1080,1081,1082,1099,1118,1888,2008,2020,2100,2375,2379,3000,3008,3128,3505,5555,6080,6648,6868,7000,7001,7002,7003,7004,7005,7007,7008,7070,7071,7074,7078,7080,7088,7200,7680,7687,7688,7777,7890,8000,8001,8002,8003,8004,8006,8008,8009,8010,8011,8012,8016,8018,8020,8028,8030,8038,8042,8044,8046,8048,8053,8060,8069,8070,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8100,8101,8108,8118,8161,8172,8180,8181,8200,8222,8244,8258,8280,8288,8300,8360,8443,8448,8484,8800,8834,8838,8848,8858,8868,8879,8880,8881,8888,8899,8983,8989,9000,9001,9002,9008,9010,9043,9060,9080,9081,9082,9083,9084,9085,9086,9087,9088,9089,9090,9091,9092,9093,9094,9095,9096,9097,9098,9099,9100,9200,9443,9448,9800,9981,9986,9988,9998,9999,10000,10001,10002,10004,10008,10010,10250,12018,12443,14000,16080,18000,18001,18002,18004,18008,18080,18082,18088,18090,18098,19001,20000,20720,21000,21501,21502,28018,20880")
   --hf value       IP文件
   -t value         线程数量 (default: 100)
   --timeout value  设置端口&URL超时 (default: 3)
   --proxy value    设置代理,例如: http://127.0.0.1:8080 | sock://127.0.0.1
   --auth value     设置sock代理认证, username:password
   --help, -h       show help
```

### `WEB`指纹识别+敏感目录探测

`-u`选择目标，`-a`开启主动目录探测，`-f`选择url文件

![image-20230615215901281](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230615215901281.png)

#### 指纹规则

提供4种指纹识别方法，内置9000+ `WEB`指纹

```
body：匹配响应体中的内容
headers：响应头中的内容
iconmd5： 匹配icon的MD5 		*可以兼容hunter*
iconhash: 匹配icon的hash 		 *可以兼容fofa*
```

#### 敏感目录探测

可敏感目录如下所示，可以`/webscan/sensitivedirectory`目录自行添加

```
axis
druid
env
fanruanoa
.git
.svn
heapdump,env
jenkins
nacos
phpmyadmin
solr
swagger-ui
thinkphp
xxl-job
tomcat-manager-page
```

### 端口扫描+端口指纹识别

仅能识别少部分指纹

```
{"FTP", "string", "FTP server"},
{"Telnet", "hex", "fffd01fffd1ffffb01fffb03"},
{"SSH", "string", "SSH-2.0"},
{"SMTP", "string", "220&."},
{"NetBIOS", "hex", "830000018f"},
{"Rsync", "string", "@RSYNCD"},
{"HTTP", "string", "HTTP/1.1|HTTP/1.0"},
{"HTTPS", "string", "HTTPS|Strict-Transport-Security"},
{"Mysql", "string", "mysql"},
{"Redis", "string", "-ERR wrong number of arguments for 'get' command"},
{"Mongodb", "string", "access MongoDB"},
{"SSL", "string", "SSL"},
外加 Oracle、Mssql、Mqtt、Memcache
```

`go run .\main.go scan -ip 127.0.0.1` 默认扫200+个端口

![image-20230624213453849](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230624213453849.png)

### 代理设置

- HTTP`-proxy http://127.0.0.1:8080`
- SOCK`-proxy sock://127.0.0.1:8080 -auth username:password`

![image-20230624211505446](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230624211505446.png)

## `bs`

使用示例 ：`go run .\main.go burst -d zjiet.edu.cn -sf .\dic.txt`

输出内容为`域名|状态码|标题|长度|Server|IP`测试在默认协程`600`的情况下，跑完需要大概4分钟

![image-20230624124019576](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230624124019576.png)

# 注意事项

`-e`会导出在`HUNTER`所能查找到的全部资产，没积分的请谨慎使用。

# 免责声明

- 本工具仅面向合法授权的企业安全建设行为与个人学习行为，如您需要测试本工具的可用性，请自行搭建靶机环境。
- 在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行扫描。

如果发现上述禁止行为，我们将保留追究您法律责任的权利。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

在安装并使用本工具前，请您务必审慎阅读、充分理解各条款内容。

除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。