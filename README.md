

<h4 align="center">Slack cli for webscan</h4>

### Usage

````
initial ws -h
````

This will display help for the tool. Here are all the switches it supports.


```bash
NAME:
   initial ws - slack cli for webscan

USAGE:
   initial ws [command options] [arguments...]

OPTIONS:
   -u value         url
   -f value         url file
   -d               enable deepScan to check more fingerprints, e.g nacos xxl-job (default: false)
   --rp             does the deep fingerprint adopt root path scanning (default: true)
   --nopoc          don't call nuclei for vulnerability scanning (default: false)
   -t value         template file or directory (default: "./config/pocs")
   --thread value   thread (default: 50)
   --timeout value  web timeout (default: 10)
   --debug          show request and response data packet (default: false)
   --proxy value    set proxy, e.g: http://127.0.0.1:8080 | sock://127.0.0.1
   --help, -h       show help
```

## Download Config

如果你是Slack的用户请将配置文件中的config文件夹移入当前工具路径下

![image-20240927000156385](assets/image-20240927000156385.png)

## Screenshot

![image-20240926161608683](assets/image-20240926161608683.png)
