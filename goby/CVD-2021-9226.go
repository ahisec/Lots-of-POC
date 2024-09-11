package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Lan Ling OA custom.jsp command execution vulnerability",
    "Description": "<p>Lanling OA is an OA office tool for instant office communication.</p><p>There is a command execution vulnerability in Lanling OA. An attacker can execute code arbitrarily on the server side, write into the back door, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Landray-OA",
    "Homepage": "http://www.landray.com.cn/",
    "DisclosureDate": "2021-08-31",
    "Author": "flyoung729@163.com",
    "FofaQuery": "((body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) ||(body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\")))",
    "GobyQuery": "((body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) ||(body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\")))",
    "Level": "3",
    "Impact": "<p>There is a command execution vulnerability in Lanling OA. An attacker can execute code arbitrarily on the server side, write into the back door, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The official has not fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.landray.com.cn\">https://www.landray.com.cn</a></p><p>1. If not necessary, prohibit the public network from accessing the device.</p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p>",
    "References": [
        "https://www.cnblogs.com/0day-li/p/14637653.html"
    ],
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
                "uri": "/loginx.jsp",
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
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "0c5b0f467a90e2484373b813ecf35a9d",
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
                "uri": "/sys/ui/extend/varkind/custom.js",
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
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Command Execution",
        "Information technology application innovation industry"
    ],
    "VulType": [
        "Command Execution"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "蓝凌OA custom.jsp 命令执行漏洞",
            "Product": "Landray-OA系统",
            "Description": "<p>蓝凌OA是用于即时办公通信的OA办公工具。</p><p>蓝凌OA存在命令执行漏洞，攻击者可以在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.landray.com.cn\">https://www.landray.com.cn</a></p><p>1、如⾮必要，禁⽌公⽹访问该设备。</p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。<br></p>",
            "Impact": "<p>蓝凌OA存在命令执行漏洞，攻击者可以在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "信创"
            ]
        },
        "EN": {
            "Name": "Lan Ling OA custom.jsp command execution vulnerability",
            "Product": "Landray-OA",
            "Description": "<p>Lanling OA is an OA office tool for instant office communication.</p><p>There is a command execution vulnerability in Lanling OA. An attacker can execute code arbitrarily on the server side, write into the back door, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The official has not fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.landray.com.cn\" rel=\"nofollow\">https://www.landray.com.cn</a></p><p>1. If not necessary, prohibit the public network from accessing the device.</p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p>",
            "Impact": "<p>There is a command execution vulnerability in Lanling OA. An attacker can execute code arbitrarily on the server side, write into the back door, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "Information technology application innovation industry"
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