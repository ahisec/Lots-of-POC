package exploits

import "git.gobies.org/goby/goscanner/goutils"

func init() {
	expJson := `{
    "Name": "Kubernetes_docker容器集群管理平台未授权访问",
    "Description": "Kubernetes_docker用于管理云平台中多个主机上的容器化的应用。Kubernetes_docker容器集群管理平台未授权访问，可获得服务器权限。",
    "Product": "kubernetes",
    "Homepage": "https://kubernetes.io/",
    "DisclosureDate": "2017-06-16",
    "Author": "vaf",
    "FofaQuery": "(title=\"Kubernetes dashboard\" || body=\"href=\\\"assets/images/kubernetes-logo.png\" || body=\"<article class=\\\"post kubernetes\" || body=\"<b>KUBERNETES</b> listening\" || body=\"value=\\\"kubernetes\" || header=\"realm=\\\"kubernetes\" || banner=\"realm=\\\"kubernetes\" || title=\"Kubernetes CI\" || ((body=\"/healthz\" || body=\"/metrics\") && body=\"paths\" && header=\"application/json\") || (((header=\"401 Unauthorized\" || header=\"403 Forbidden\") && header=\"Audit-Id\") || header=\"X-Kubernetes-Pf-Flowschema-Uid\") || (((banner=\"401 Unauthorized\" || banner=\"403 Forbidden\") && banner=\"Audit-Id\") || banner=\"X-Kubernetes-Pf-Flowschema-Uid\") || title==\"Kubernetes Dashboard\" || title==\"Ingress Default Backend - 404 Not Found\" || title==\"Mirantis Kubernetes Engine\" || title=\"Kubernetes Operational View\")",
    "Level": "3",
    "Impact": "<p>一、kubernetes未授权访问，导致访问用户可以创建、修改、删除容器，查看日志等。甚至获取服务器权限。</p><p>二、可能导致服务器重要数字资源被盗窃。</p>",
    "Recommendation": "<p>一、可以增加鉴权，1，密码不少于6位。2，需要包含字母，数字，标点符号。</p><p>二、将重要资源文件进行权限管理。</p><p>三、将重要的管理文件进行加密</p>",
    "References": [
        "https://0x0d.im/archives/attack-container-management-platform.html"
    ],
    "HasExp": false,
    "ExpParams": [],
    "is0day": false,
    "ExpTips": {
        "type": "Tips",
        "content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/api/v1/proxy/namespaces/kube-system/services/kubernetes-dashboard/",
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
                        "value": "assets/images/kubernetes-logo.png",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/api/appConfig.json",
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
                        "value": "appConfig_DO_NOT_USE_DIRECTLY ",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Posttime": "2018-10-22 21:25:44",
    "fofacli_version": "3.0.8",
    "fofascan_version": "0.1.16",
    "status": "0",
    "CveID": "",
    "CNNVD": [],
    "CNVD": [],
    "CVSS": "9.8",
    "Tags": [
        "未授权访问"
    ],
    "VulType": [
        "未授权访问"
    ],
    "GobyQuery": "(title=\"Kubernetes dashboard\" || body=\"href=\\\"assets/images/kubernetes-logo.png\" || body=\"<article class=\\\"post kubernetes\" || body=\"<b>KUBERNETES</b> listening\" || body=\"value=\\\"kubernetes\" || header=\"realm=\\\"kubernetes\" || banner=\"realm=\\\"kubernetes\" || title=\"Kubernetes CI\" || ((body=\"/healthz\" || body=\"/metrics\") && body=\"paths\" && header=\"application/json\") || (((header=\"401 Unauthorized\" || header=\"403 Forbidden\") && header=\"Audit-Id\") || header=\"X-Kubernetes-Pf-Flowschema-Uid\") || (((banner=\"401 Unauthorized\" || banner=\"403 Forbidden\") && banner=\"Audit-Id\") || banner=\"X-Kubernetes-Pf-Flowschema-Uid\") || title==\"Kubernetes Dashboard\" || title==\"Ingress Default Backend - 404 Not Found\" || title==\"Mirantis Kubernetes Engine\" || title=\"Kubernetes Operational View\")",
    "PocId": "10810"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
