# 使用说明

首先运行`go run .\main.go -h`会在当前目录下生成一个config.json的文件，在其中配置正确的hunter-api即可使用。

![image-20230524234259910](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230524234259910.png)

`go run main.go -h`，功能主要分布在子命令`info`和`scan`中

![image-20230615000840567](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230615000840567.png)

## `info`

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
   -b value  指定子域名字典文件,开启子域名暴破功能
   -c value  需要进行查询的ICP名称
   -f value  指定需要进行查询ICP名称文件
   -m value  是否需要导出HUNTER资产文件(开启去重功能),-n数量不为0才会导出
      0 - 仅导出查询ICP资产
      1 - 仅导出域名ICP资产
      2 - ICP资产和域名资产都导出(会有重复资产) (default: 0)
   -e value    是否导出资产
   -w          进行一级全资子公司查询和ICP备案名反查域名(会自动纠正ICP名称,但是有误报概率) (default: false)
   --help, -h  show help
```

| **初衷：** | **为大型活动`hvv`进行信息收集以及资产甄别（快速找出资产多的软柿子）** |
| ---------- | ------------------------------------------------------------ |
| **提示：** | **在查询`hunter api`接口时，每次只会查询1条记录，查询一家单位备案仅消耗1积分，1个域名也是1积分，所以可以不必担心浪费大量积分的情况，由于`hunter api`查询速度限制，每次查询延时2秒。** |
| **注意：** | **由于`ICP`查域名爬的`https://www.beianx.cn`是个人网站，所以会出现域名反查遗漏的现象。** |

### 全资子公司查询+反查域名

`-w`参数开启子公司查询模式，子域名资产信息以及名称纠正功能来自天眼查。

![image-20230615000520027](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230615000520027.png)

### 子域名暴破

`-b`参数指定子域字典目录后，会对反查到的域名进行子域名暴破，可过泛解析，解析超过3次的IP会被拉入黑名单。

![image-20230615091957046](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230615091957046.png)

### `HUNTER`结果导出

`go run .\main.go info -c "浙江红狮水泥股份有限公司" -m 0 -e`，结果输出再`/report/assetxxx.csv`

![image-20230615160915739](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230615160915739.png)

## `scan`

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
   initial scan - 使用资产扫描模块,可以用于目标指纹探测,敏感目录探测

USAGE:
   initial scan [command options] [arguments...]

OPTIONS:
   -a          是否开启主动探测 (default: false)
   -u value    目标URL
   -f value    目标URL文件
   -t value    指定线程数量 (default: 100)
   --help, -h  show help
```

### 指纹识别+敏感目录探测

`-u`选择目标，`-a`开启主动目录探测，`-f`选择url文件

![image-20230615215901281](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230615215901281.png)

可敏感目录如下所示，可以自行添加

![image-20230615104300079](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230615104300079.png)

# 结果输出

不指定-o会默认名为result.csv的文件，每次运行前建议删除result.csv会指定一个新的名字（不然好像会写入失败） `-o xxhw`不用加后缀

![image-20230602222450658](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230602222450658.png)

# 注意事项

由于hunter api限制，t只能等于*1,10,20,50,100*，其他参数存在报错，考虑到积分问题也不建议大于100导出，所以不增加该实现大量导出的方法（通过控制page翻页可以实现）。

![image-20230524230432047](https://qwtd-image.oss-cn-hangzhou.aliyuncs.com/img/image-20230524230432047.png)

# 打包

点击bat文件会将各系统的可执行文件输出至release目录下（需要go环境）