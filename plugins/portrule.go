package plugins

type PortRule struct {
	Name   string
	Format string
	Rule   string
}

var PortRules = []PortRule{
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
}

// 这几项数据包可以检测是否存在未授权
var (
	Reids     = []byte("*1\r\n$4\r\nPING\r\n")
	MongoDB   = []byte{72, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 212, 7, 0, 0, 0, 0, 0, 0, 97, 100, 109, 105, 110, 46, 36, 99, 109, 100, 0, 0, 0, 0, 0, 1, 0, 0, 0, 33, 0, 0, 0, 2, 103, 101, 116, 76, 111, 103, 0, 16, 0, 0, 0, 115, 116, 97, 114, 116, 117, 112, 87, 97, 114, 110, 105, 110, 103, 115, 0, 0}
	Memcached = []byte("version\r\n")
)

// smb&netbios|oracle|mssql|mqtt单独模块包

// rdp 3389
