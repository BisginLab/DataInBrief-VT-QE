# import requests

# API_KEY = 'f8c4555f34f9900ea49bb4648073458467ecce535377870926b38b694f6bc7c6'

# url = 'https://www.virustotal.com/api/v3/intelligence/search'
# file_hash = '7bd6492106c1e6b60302df04babc7279'
# params = {
#     "query": "crowdsourced_ai_verdict:malicious AND {file_hash}"
# }
# print(requests.get(url, params=params, headers={'x-Apikey': API_KEY}).json())


#<Response [401]>

# r_quota = requests.get(QUOTA_URL.format(id = API_KEY), headers={'x-apikey': API_KEY})
import tiktoken
file = """{
    "md5": "0a056e63a076f4b0ce8fdad1790cac55",
    "apk_filename": "com.pro.fot.mar.sanv2.apk",
    "size_bytes": 20363720,
    "threat_level": "Moderate Risk",
    "total_score": 211,
    "crimes": [
        {
            "rule": "00157.json",
            "crime": "Instantiate new object using reflection, possibly used for dexClassLoader ",
            "label": [
                "reflection",
                "dexClassLoader"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00092.json",
            "crime": "Send broadcast",
            "label": [
                "command"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lcom/pro/lib/a/a;",
                    "method": "getApplicationContext",
                    "descriptor": "()Landroid/content/Context;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00145.json",
            "crime": "Create a socket connection to the proxy address",
            "label": [
                "network",
                "command"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00042.json",
            "crime": "Query WiFi BSSID and scan results",
            "label": [
                "collection",
                "wifi"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00201.json",
            "crime": "Query data from the call log",
            "label": [
                "collection",
                "calllog"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;",
                    "match_keywords": [
                        "call_log"
                    ]
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; onActivityResult (I I Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual/range",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "v6",
                            "v7",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "first_hex": "74 06 57 00 02 00",
                        "second": [
                            "invoke-interface",
                            "v3",
                            "v0",
                            "Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I"
                        ],
                        "second_hex": "72 20 d9 00 03 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00098.json",
            "crime": "Check if the network is connected",
            "label": [
                "network"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/NetworkInfo;",
                    "method": "isConnected",
                    "descriptor": "()Z"
                },
                {
                    "class": "Ljava/lang/Object;",
                    "method": "equals",
                    "descriptor": "(Ljava/lang/Object;)Z"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Z",
                    "class": "Landroid/net/NetworkInfo;",
                    "method": "isConnected"
                },
                {
                    "descriptor": "(Ljava/lang/Object;)Z",
                    "class": "Ljava/lang/Object;",
                    "method": "equals"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00007.json",
            "crime": "Use absolute path of directory for the output media file path",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00009.json",
            "crime": "Put data in cursor to JSON object",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getString",
                    "descriptor": "(I)Ljava/lang/String;"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getString",
                    "descriptor": "(I)Ljava/lang/String;"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00137.json",
            "crime": "Get last known location of the device",
            "label": [
                "location",
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00052.json",
            "crime": "Deletes media specified by a content URI(SMS, CALL_LOG, File, etc.)",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "delete",
                    "descriptor": "(Landroid/net/Uri; Ljava/lang/String; [Ljava/lang/String;)I"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "delete",
                    "descriptor": "(Landroid/net/Uri; Ljava/lang/String; [Ljava/lang/String;)I"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00207.json",
            "crime": "Check if the resource name of the view contains the given string",
            "label": [
                "accessibility service"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/String;",
                    "method": "contains",
                    "descriptor": "(Ljava/lang/CharSequence;)Z"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00190.json",
            "crime": "Query a URI and append the result into a string",
            "label": [
                "collection",
                "sms",
                "calllog",
                "calendar"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "append",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/StringBuilder;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "append",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/StringBuilder;"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; onActivityResult (I I Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual/range",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "v6",
                            "v7",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "first_hex": "74 06 57 00 02 00",
                        "second": [
                            "invoke-virtual",
                            "v12",
                            "Lcom/pro/lib/libreriafotografia/b;->j()V"
                        ],
                        "second_hex": "6e 10 51 23 0c 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00099.json",
            "crime": "Get location of the current GSM and put it into JSON",
            "label": [
                "collection",
                "location"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00176.json",
            "crime": "Send sms to a contact of contact list",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0,
            "confidence": "0%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00075.json",
            "crime": "Get location of the device",
            "label": [
                "collection",
                "location"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00146.json",
            "crime": "Get the network operator name and IMSI",
            "label": [
                "telephony",
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00131.json",
            "crime": "Get location of the current GSM and put it into JSON",
            "label": [
                "collection",
                "location"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00043.json",
            "crime": "Calculate WiFi signal strength",
            "label": [
                "collection",
                "wifi"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00086.json",
            "crime": "Check if the device is in data roaming mode",
            "label": [
                "telephony"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Object;",
                    "method": "equals",
                    "descriptor": "(Ljava/lang/Object;)Z"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00100.json",
            "crime": "Check the network capabilities",
            "label": [
                "collection",
                "network"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Object;",
                    "method": "equals",
                    "descriptor": "(Ljava/lang/Object;)Z"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00189.json",
            "crime": "Get the content of a SMS message",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;",
                    "match_keywords": [
                        "sms"
                    ]
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I",
                    "match_keywords": [
                        "body"
                    ]
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; onActivityResult (I I Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual/range",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "v6",
                            "v7",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "first_hex": "74 06 57 00 02 00",
                        "second": [
                            "invoke-interface",
                            "v3",
                            "v0",
                            "Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I"
                        ],
                        "second_hex": "72 20 d9 00 03 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00195.json",
            "crime": "Set the output path of the recorded file",
            "label": [
                "record",
                "file"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00072.json",
            "crime": "Write HTTP input stream into a file",
            "label": [
                "command",
                "network",
                "file"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "getInputStream",
                    "descriptor": "()Ljava/io/InputStream;"
                },
                {
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write",
                    "descriptor": "([B I I)V"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Ljava/io/InputStream;",
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "getInputStream"
                },
                {
                    "descriptor": "([B I I)V",
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00040.json",
            "crime": "Send SMS",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00097.json",
            "crime": "Get the sender address of the SMS and put it into JSON",
            "label": [
                "collection",
                "sms"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00153.json",
            "crime": "Send binary data over HTTP",
            "label": [
                "http"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [
                "android.permission.INTERNET"
            ],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00202.json",
            "crime": "Make a phone call",
            "label": [
                "control"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Intent;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String;)V"
                },
                {
                    "class": "Landroid/content/Intent;",
                    "method": "setData",
                    "descriptor": "(Landroid/net/Uri;)Landroid/content/Intent;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/Intent;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String;)V",
                    "match_keywords": [
                        "CALL"
                    ]
                },
                {
                    "class": "Landroid/content/Intent;",
                    "method": "setData",
                    "descriptor": "(Landroid/net/Uri;)Landroid/content/Intent;"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/ge; a (Ljava/lang/String;)Landroid/content/Intent;": {
                        "first": [
                            "invoke-direct",
                            "v1",
                            "v2",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 21 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 01 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonDiverCaraFotoStudio (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizBanderas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal5 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosFun (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosAmigos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionCollageOpcion (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosSanValentin (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal4 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLocalCars (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLocalChistes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal1 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesDosTres (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionIlusionesOpticas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; e ()V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosUno (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcoFotosFutbolDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionIlusionesOpticas2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveFunMontages2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosDisfraces (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosIncreibles2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPhotoCollageEditor2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizGeografia (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFunLoveFrames (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonLoveTesterMatchCalculator (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveFun2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionOldMontajes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosInf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoMontajesBillboard (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPersonalPostCards (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonTourismSimulator (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; b ()V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/ge; c (Ljava/lang/String;)Landroid/content/Intent;": {
                        "first": [
                            "invoke-direct",
                            "v1",
                            "v2",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 21 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 01 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionTarjetas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonFunPhotoCollageStudio (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosSV3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonBillboardDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesEsp (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; b ()V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionYourPersonalLovePostCardAPP (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFraProf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesEsp2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal9 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFrasesAmistad2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizFootballMund (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetasAmor2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal10 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveTest (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFraAmis (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosIncreibles (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizCoches (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/ge; b (Ljava/lang/String;)Landroid/content/Intent;": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFotosDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPhotoCollageEditor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetasAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizFutbol (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonFunBackgroundChanger (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonMagicCamera (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoMontajesSanValen2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosFutbol (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoWarp (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal7 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesFunGentleman (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFramesAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; e ()V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal6 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonCollageMaker (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFraProf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosKids3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosInf2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFunnyFaceYou (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonPIP2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionTarjetasAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFraAmis (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizLocal3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonRealLovePhotoFrame (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesBrasil (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizBrasil (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00054.json",
            "crime": "Install other APKs from file",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Intent;",
                    "method": "setDataAndType",
                    "descriptor": "(Landroid/net/Uri; Ljava/lang/String;)Landroid/content/Intent;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00183.json",
            "crime": "Get current camera paremeters and change the setting.",
            "label": [
                "camera"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "getParameters",
                    "descriptor": "()Landroid/hardware/Camera$Parameters;"
                },
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "setParameters",
                    "descriptor": "(Landroid/hardware/Camera$Parameters;)V"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "getParameters",
                    "descriptor": "()Landroid/hardware/Camera$Parameters;"
                },
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "setParameters",
                    "descriptor": "(Landroid/hardware/Camera$Parameters;)V"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; o ()V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/hardware/Camera;->getParameters()Landroid/hardware/Camera$Parameters;"
                        ],
                        "first_hex": "6e 10 a1 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Landroid/hardware/Camera;->setParameters(Landroid/hardware/Camera$Parameters;)V"
                        ],
                        "second_hex": "6e 20 a5 01 01 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/a; surfaceChanged (Landroid/view/SurfaceHolder; I I I)V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/hardware/Camera;->getParameters()Landroid/hardware/Camera$Parameters;"
                        ],
                        "first_hex": "6e 10 a1 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Landroid/hardware/Camera;->setParameters(Landroid/hardware/Camera$Parameters;)V"
                        ],
                        "second_hex": "6e 20 a5 01 01 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; o ()V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/hardware/Camera;->getParameters()Landroid/hardware/Camera$Parameters;"
                        ],
                        "first_hex": "6e 10 a1 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Landroid/hardware/Camera;->setParameters(Landroid/hardware/Camera$Parameters;)V"
                        ],
                        "second_hex": "6e 20 a5 01 01 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/a; surfaceChanged (Landroid/view/SurfaceHolder; I I I)V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/hardware/Camera;->getParameters()Landroid/hardware/Camera$Parameters;"
                        ],
                        "first_hex": "6e 10 a1 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Landroid/hardware/Camera;->setParameters(Landroid/hardware/Camera$Parameters;)V"
                        ],
                        "second_hex": "6e 20 a5 01 01 00"
                    }
                }
            ]
        },
        {
            "rule": "00038.json",
            "crime": "Query the phone number",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00197.json",
            "crime": "Set the audio encoder and initialize the recorder",
            "label": [
                "record"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00152.json",
            "crime": "Get data from HTTP and send SMS",
            "label": [
                "command",
                "sms"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [
                "android.permission.INTERNET"
            ],
            "native_api": [
                {
                    "class": "Ljava/net/URL;",
                    "method": "openConnection",
                    "descriptor": "()Ljava/net/URLConnection;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00206.json",
            "crime": "Check if the text of the view contains the given string",
            "label": [
                "accessibility service"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/String;",
                    "method": "contains",
                    "descriptor": "(Ljava/lang/CharSequence;)Z"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00110.json",
            "crime": "Query the ICCID number",
            "label": [
                "collection",
                "telephony"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00208.json",
            "crime": "Capture the contents of the device screen",
            "label": [
                "collection",
                "screen"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00120.json",
            "crime": "Append the sender's address to the string",
            "label": [
                "sms",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "append",
                    "descriptor": "(I)Ljava/lang/StringBuilder;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00014.json",
            "crime": "Read file into a stream and put it into a JSON object",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileInputStream;",
                    "method": "<init>",
                    "descriptor": "(Ljava/io/File;)V"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/io/FileInputStream;",
                    "method": "<init>",
                    "descriptor": "(Ljava/io/File;)V"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00028.json",
            "crime": "Read file from assets directory",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/res/AssetManager;",
                    "method": "open",
                    "descriptor": "(Ljava/lang/String;)Ljava/io/InputStream;"
                },
                {
                    "class": "Ljava/io/InputStream;",
                    "method": "read",
                    "descriptor": "([B)I"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/res/AssetManager;",
                    "method": "open",
                    "descriptor": "(Ljava/lang/String;)Ljava/io/InputStream;"
                },
                {
                    "class": "Ljava/io/InputStream;",
                    "method": "read",
                    "descriptor": "([B)I"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00022.json",
            "crime": "Open a file from given absolute path of the file",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Ljava/io/File;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String;)V"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Ljava/io/File;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String;)V"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00006.json",
            "crime": "Scheduling recording task",
            "label": [
                "record"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00035.json",
            "crime": "Query the list of the installed packages",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getPackageManager",
                    "descriptor": "()Landroid/content/pm/PackageManager;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00070.json",
            "crime": "Get sender's address and send SMS",
            "label": [
                "collection",
                "command",
                "sms"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00151.json",
            "crime": "Send phone number over Internet",
            "label": [
                "phone",
                "privacy"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [
                "android.permission.INTERNET"
            ],
            "native_api": [
                {
                    "class": "Ljava/net/URL;",
                    "method": "openConnection",
                    "descriptor": "()Ljava/net/URLConnection;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00171.json",
            "crime": "Compare network operator with a string",
            "label": [
                "network"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/String;",
                    "method": "equals",
                    "descriptor": "(Ljava/lang/Object;)Z"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00089.json",
            "crime": "Connect to a URL and receive input stream from the server",
            "label": [
                "command",
                "network"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/net/URL;",
                    "method": "openConnection",
                    "descriptor": "()Ljava/net/URLConnection;"
                },
                {
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "getInputStream",
                    "descriptor": "()Ljava/io/InputStream;"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Ljava/net/URLConnection;",
                    "class": "Ljava/net/URL;",
                    "method": "openConnection"
                },
                {
                    "descriptor": "()Ljava/io/InputStream;",
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "getInputStream"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/de; a (Landroid/content/Context; Ljava/lang/String; Ljava/lang/String;)Lcom/google/android/gms/internal/cf;": {
                        "first": [
                            "invoke-virtual",
                            "v2",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 02 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;"
                        ],
                        "second_hex": "6e 10 b5 26 00 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/ez; a (Landroid/content/Context; Ljava/lang/String; Ljava/lang/String;)Landroid/webkit/WebResourceResponse;": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;"
                        ],
                        "second_hex": "6e 10 b5 26 00 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/google/android/gms/internal/de; a (Landroid/content/Context; Ljava/lang/String; Ljava/lang/String;)Lcom/google/android/gms/internal/cf;": {
                        "first": [
                            "invoke-virtual",
                            "v2",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 02 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;"
                        ],
                        "second_hex": "6e 10 b5 26 00 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/ez; a (Landroid/content/Context; Ljava/lang/String; Ljava/lang/String;)Landroid/webkit/WebResourceResponse;": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;"
                        ],
                        "second_hex": "6e 10 b5 26 00 00"
                    }
                }
            ]
        },
        {
            "rule": "00178.json",
            "crime": "Execute Linux commands via ProcessBuilder",
            "label": [
                "command"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00096.json",
            "crime": "Connect to a URL and set request method",
            "label": [
                "command",
                "network"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/net/URL;",
                    "method": "openConnection",
                    "descriptor": "()Ljava/net/URLConnection;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00139.json",
            "crime": "Get the current WiFi id",
            "label": [
                "collection",
                "wifi"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00191.json",
            "crime": "Get messages in the SMS inbox",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;",
                    "match_keywords": [
                        "sms/inbox"
                    ]
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00051.json",
            "crime": "Implicit intent(view a web page, make a phone call, etc.) via setData",
            "label": [
                "control"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/Intent;",
                    "method": "setData",
                    "descriptor": "(Landroid/net/Uri;)Landroid/content/Intent;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/Intent;",
                    "method": "setData",
                    "descriptor": "(Landroid/net/Uri;)Landroid/content/Intent;"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonDiverCaraFotoStudio (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizBanderas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal5 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosFun (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosAmigos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionCollageOpcion (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosSanValentin (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal4 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLocalCars (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLocalChistes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal1 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesDosTres (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionIlusionesOpticas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; e ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosUno (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcoFotosFutbolDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveFunMontages2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionIlusionesOpticas2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosDisfraces (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosIncreibles2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPhotoCollageEditor2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizGeografia (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFunLoveFrames (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonLoveTesterMatchCalculator (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveFun2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionOldMontajes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosInf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoMontajesBillboard (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPersonalPostCards (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/bl; a (Landroid/content/Context; Lcom/google/android/gms/internal/bn; Lcom/google/android/gms/internal/bz;)Z": {
                        "first": [
                            "invoke-static",
                            "v3",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 03 00",
                        "second": [
                            "invoke-virtual",
                            "v2",
                            "v3",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 32 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonTourismSimulator (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; b ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/ge; c (Ljava/lang/String;)Landroid/content/Intent;": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 01 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionTarjetas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonFunPhotoCollageStudio (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosSV3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonBillboardDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesEsp (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; b ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionYourPersonalLovePostCardAPP (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFraProf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesEsp2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal9 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFrasesAmistad2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizFootballMund (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetasAmor2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal10 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveTest (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFraAmis (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosIncreibles (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizCoches (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFotosDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPhotoCollageEditor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetasAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizFutbol (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonFunBackgroundChanger (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonMagicCamera (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoMontajesSanValen2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosFutbol (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoWarp (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal7 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesFunGentleman (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFramesAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; e ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal6 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonCollageMaker (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFraProf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosKids3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosInf2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFunnyFaceYou (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonPIP2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionTarjetasAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFraAmis (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizLocal3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonRealLovePhotoFrame (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesBrasil (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizBrasil (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonDiverCaraFotoStudio (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizBanderas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal5 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosFun (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosAmigos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionCollageOpcion (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosSanValentin (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal4 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLocalCars (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLocalChistes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal1 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesDosTres (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionIlusionesOpticas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; e ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosUno (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcoFotosFutbolDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveFunMontages2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionIlusionesOpticas2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosDisfraces (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosIncreibles2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPhotoCollageEditor2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizGeografia (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFunLoveFrames (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonLoveTesterMatchCalculator (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveFun2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionOldMontajes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosInf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoMontajesBillboard (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPersonalPostCards (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/bl; a (Landroid/content/Context; Lcom/google/android/gms/internal/bn; Lcom/google/android/gms/internal/bz;)Z": {
                        "first": [
                            "invoke-static",
                            "v3",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 03 00",
                        "second": [
                            "invoke-virtual",
                            "v2",
                            "v3",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 32 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonTourismSimulator (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; b ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/ge; c (Ljava/lang/String;)Landroid/content/Intent;": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 01 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionTarjetas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonFunPhotoCollageStudio (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosSV3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonBillboardDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesEsp (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; b ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionYourPersonalLovePostCardAPP (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFraProf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesEsp2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal9 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFrasesAmistad2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizFootballMund (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetasAmor2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal10 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveTest (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFraAmis (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosIncreibles (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizCoches (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFotosDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPhotoCollageEditor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetasAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizFutbol (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonFunBackgroundChanger (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonMagicCamera (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoMontajesSanValen2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosFutbol (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoWarp (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal7 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesFunGentleman (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFramesAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; e ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal6 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonCollageMaker (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFraProf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosKids3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosInf2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFunnyFaceYou (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonPIP2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionTarjetasAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFraAmis (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizLocal3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonRealLovePhotoFrame (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesBrasil (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizBrasil (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                }
            ]
        },
        {
            "rule": "00021.json",
            "crime": "Load additional DEX files dynamically",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Ljava/lang/ClassLoader;",
                    "method": "loadClass",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Ljava/lang/ClassLoader;",
                    "method": "loadClass",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00045.json",
            "crime": "Query the name of currently running application",
            "label": [
                "collection",
                "reflection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00033.json",
            "crime": "Query the IMEI number",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00078.json",
            "crime": "Get the network operator name",
            "label": [
                "collection",
                "telephony"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00026.json",
            "crime": "Method reflection",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getMethod",
                    "descriptor": "(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                },
                {
                    "class": "Ljava/lang/reflect/Method;",
                    "method": "invoke",
                    "descriptor": "(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getMethod",
                    "descriptor": "(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                },
                {
                    "class": "Ljava/lang/reflect/Method;",
                    "method": "invoke",
                    "descriptor": "(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/kp; a (Ljava/lang/String; Ljava/lang/Object; Ljava/lang/StringBuffer; Ljava/lang/StringBuffer;)V": {
                        "first": [
                            "invoke-virtual",
                            "v5",
                            "v0",
                            "v8",
                            "Ljava/lang/Class;->getMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "first_hex": "6e 30 d6 25 05 08",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v12",
                            "v8",
                            "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                        ],
                        "second_hex": "6e 30 a5 26 c0 08"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/fb; b (Lcom/google/android/gms/internal/fb$a;)Ljava/lang/Object;": {
                        "first": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "v2",
                            "Ljava/lang/Class;->getMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "first_hex": "6e 30 d6 25 01 02",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v4",
                            "v1",
                            "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                        ],
                        "second_hex": "6e 30 a5 26 40 01"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/google/android/gms/internal/kp; a (Ljava/lang/String; Ljava/lang/Object; Ljava/lang/StringBuffer; Ljava/lang/StringBuffer;)V": {
                        "first": [
                            "invoke-virtual",
                            "v5",
                            "v0",
                            "v8",
                            "Ljava/lang/Class;->getMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "first_hex": "6e 30 d6 25 05 08",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v12",
                            "v8",
                            "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                        ],
                        "second_hex": "6e 30 a5 26 c0 08"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/fb; b (Lcom/google/android/gms/internal/fb$a;)Ljava/lang/Object;": {
                        "first": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "v2",
                            "Ljava/lang/Class;->getMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "first_hex": "6e 30 d6 25 01 02",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v4",
                            "v1",
                            "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                        ],
                        "second_hex": "6e 30 a5 26 40 01"
                    }
                }
            ]
        },
        {
            "rule": "00136.json",
            "crime": "Stop recording",
            "label": [
                "record",
                "command"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00172.json",
            "crime": "Check Admin permissions to (probably) get them",
            "label": [
                "admin"
            ],
            "score": 1,
            "weight": 0,
            "confidence": "0%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00004.json",
            "crime": "Get filename and put it to JSON object",
            "label": [
                "file",
                "collection"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getName",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getName",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00095.json",
            "crime": "Write the ICCID of device into a file",
            "label": [
                "collection",
                "telephony"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write",
                    "descriptor": "([B)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00017.json",
            "crime": "Get Location of the device and append this info to a string",
            "label": [
                "location",
                "collection"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/location/Location;",
                    "method": "getLatitude",
                    "descriptor": "()D"
                },
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "append",
                    "descriptor": "(D)Ljava/lang/StringBuilder;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/location/Location;",
                    "method": "getLatitude",
                    "descriptor": "()D"
                },
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "append",
                    "descriptor": "(D)Ljava/lang/StringBuilder;"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00140.json",
            "crime": "Write the phone number into a file",
            "label": [
                "collection",
                "telephony",
                "file",
                "command"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write",
                    "descriptor": "([B)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00016.json",
            "crime": "Get location info of the device and put it to JSON object",
            "label": [
                "location",
                "collection"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/location/Location;",
                    "method": "getLongitude",
                    "descriptor": "()D"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/location/Location;",
                    "method": "getLongitude",
                    "descriptor": "()D"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/dg; a (Lcom/google/android/gms/internal/cd; Lcom/google/android/gms/internal/dm; Landroid/location/Location;)Ljava/lang/String;": {
                        "first": [
                            "invoke-static",
                            "v2",
                            "v0",
                            "Lcom/google/android/gms/internal/dg;->a(Ljava/util/HashMap; Landroid/location/Location;)V"
                        ],
                        "first_hex": "71 20 f8 17 02 00",
                        "second": [
                            "invoke-static",
                            "v2",
                            "Lcom/google/android/gms/internal/dz;->a(Ljava/util/Map;)Lorg/json/JSONObject;"
                        ],
                        "second_hex": "71 10 58 18 02 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00061.json",
            "crime": "Return dynamic information about the current Wi-Fi connection",
            "label": [
                "wifi",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Integer;",
                    "method": "valueOf",
                    "descriptor": "(I)Ljava/lang/Integer;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00129.json",
            "crime": "Get the content of SMS",
            "label": [
                "sms",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/String;",
                    "method": "toString",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00165.json",
            "crime": "Get SMS message body and send it through http",
            "label": [
                "sms",
                "http"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00020.json",
            "crime": "Get absolute path of the file and store in string",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "toString",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "toString",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/ligreriagaleriafolderpicasso/j; a ()[Ljava/lang/String;": {
                        "first": [
                            "invoke-virtual",
                            "v8",
                            "Ljava/io/File;->getAbsolutePath()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 8a 25 08 00",
                        "second": [
                            "invoke-virtual",
                            "v7",
                            "Ljava/lang/StringBuilder;->toString()Ljava/lang/String;"
                        ],
                        "second_hex": "6e 10 72 26 07 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/pro/lib/ligreriagaleriafolderpicasso/j; a ()[Ljava/lang/String;": {
                        "first": [
                            "invoke-virtual",
                            "v8",
                            "Ljava/io/File;->getAbsolutePath()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 8a 25 08 00",
                        "second": [
                            "invoke-virtual",
                            "v7",
                            "Ljava/lang/StringBuilder;->toString()Ljava/lang/String;"
                        ],
                        "second_hex": "6e 10 72 26 07 00"
                    }
                }
            ]
        },
        {
            "rule": "00121.json",
            "crime": "Create a directory",
            "label": [
                "file",
                "command"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                },
                {
                    "class": "Ljava/io/File;",
                    "method": "mkdirs",
                    "descriptor": "()Z"
                }
            ],
            "combination": [
                {
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;",
                    "class": "Landroid/os/Bundle;",
                    "method": "getString"
                },
                {
                    "descriptor": "()Z",
                    "class": "Ljava/io/File;",
                    "method": "mkdirs"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00138.json",
            "crime": "Set the audio source (MIC)",
            "label": [
                "record"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00182.json",
            "crime": "Open camera.",
            "label": [
                "camera"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "open",
                    "descriptor": "(I)Landroid/hardware/Camera;"
                },
                {
                    "class": "Ljava/lang/Object;",
                    "method": "<init>",
                    "descriptor": "()V"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "open",
                    "descriptor": "(I)Landroid/hardware/Camera;"
                },
                {
                    "class": "Ljava/lang/Object;",
                    "method": "<init>",
                    "descriptor": "()V"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00057.json",
            "crime": "Return the DHCP-assigned addresses from the last successful DHCP request",
            "label": [
                "network",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "toString",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00150.json",
            "crime": "Send IMSI over Internet",
            "label": [
                "phone"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [
                "android.permission.INTERNET"
            ],
            "native_api": [
                {
                    "class": "Ljava/net/URL;",
                    "method": "openConnection",
                    "descriptor": "()Ljava/net/URLConnection;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00082.json",
            "crime": "Get the current WiFi MAC address",
            "label": [
                "collection",
                "wifi"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00164.json",
            "crime": "Get SMS address and send it through http",
            "label": [
                "sms",
                "http"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00170.json",
            "crime": "Get installed applications and put the list in shared preferences",
            "label": [
                "applications",
                "privacy"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00059.json",
            "crime": "Query the SIM card status",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Integer;",
                    "method": "intValue",
                    "descriptor": "()I"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00105.json",
            "crime": "Append the sender's address to the string",
            "label": [
                "collection",
                "sms"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "append",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/StringBuilder;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00160.json",
            "crime": "Use accessibility service to perform action getting node info by View Id",
            "label": [
                "accessibility service"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00031.json",
            "crime": "Check the list of currently running applications",
            "label": [
                "reflection",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ComponentName;",
                    "method": "getPackageName",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00109.json",
            "crime": "Connect to a URL and get the response code",
            "label": [
                "network",
                "command"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/net/URL;",
                    "method": "openConnection",
                    "descriptor": "()Ljava/net/URLConnection;"
                },
                {
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "getResponseCode",
                    "descriptor": "()I"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Ljava/net/URLConnection;",
                    "class": "Ljava/net/URL;",
                    "method": "openConnection"
                },
                {
                    "descriptor": "()I",
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "getResponseCode"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/de; a (Landroid/content/Context; Ljava/lang/String; Ljava/lang/String;)Lcom/google/android/gms/internal/cf;": {
                        "first": [
                            "invoke-virtual",
                            "v2",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 02 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->getResponseCode()I"
                        ],
                        "second_hex": "6e 10 b6 26 00 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/ef; a ()V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->getResponseCode()I"
                        ],
                        "second_hex": "6e 10 b6 26 00 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/google/android/gms/internal/de; a (Landroid/content/Context; Ljava/lang/String; Ljava/lang/String;)Lcom/google/android/gms/internal/cf;": {
                        "first": [
                            "invoke-virtual",
                            "v2",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 02 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->getResponseCode()I"
                        ],
                        "second_hex": "6e 10 b6 26 00 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/ef; a ()V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->getResponseCode()I"
                        ],
                        "second_hex": "6e 10 b6 26 00 00"
                    }
                }
            ]
        },
        {
            "rule": "00162.json",
            "crime": "Create InetSocketAddress object and connecting to it",
            "label": [
                "socket"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00023.json",
            "crime": "Start another application from current application",
            "label": [
                "reflection",
                "control"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "startActivity",
                    "descriptor": "(Landroid/content/Intent;)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00181.json",
            "crime": "Load native libraries(.so) via System.load (60% means caught)",
            "label": [
                "so"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00067.json",
            "crime": "Query the IMSI number",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00173.json",
            "crime": "Get bounds in screen of an AccessibilityNodeInfo and perform action",
            "label": [
                "accessibility service"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00107.json",
            "crime": "Write the IMSI number into a file",
            "label": [
                "collection",
                "telephony",
                "file",
                "command"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write",
                    "descriptor": "([B)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00168.json",
            "crime": "Use accessibility service to perform global action getting node info by text",
            "label": [
                "accessibility service"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00084.json",
            "crime": "Get the ISO country code and IMSI",
            "label": [
                "collection",
                "telephony"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00111.json",
            "crime": "Get the sender address of the SMS",
            "label": [
                "collection",
                "sms"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/String;",
                    "method": "toString",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00048.json",
            "crime": "Query the SMS contents",
            "label": [
                "sms",
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00198.json",
            "crime": "Initialize the recorder and start recording",
            "label": [
                "record"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00104.json",
            "crime": "Check if the given path is directory",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00002.json",
            "crime": "Open the camera and take picture",
            "label": [
                "camera"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "open",
                    "descriptor": "(I)Landroid/hardware/Camera;"
                },
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "takePicture",
                    "descriptor": "(Landroid/hardware/Camera$ShutterCallback; Landroid/hardware/Camera$PictureCallback; Landroid/hardware/Camera$PictureCallback;)V"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "open",
                    "descriptor": "(I)Landroid/hardware/Camera;"
                },
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "takePicture",
                    "descriptor": "(Landroid/hardware/Camera$ShutterCallback; Landroid/hardware/Camera$PictureCallback; Landroid/hardware/Camera$PictureCallback;)V"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00005.json",
            "crime": "Get absolute path of file and put it to JSON object",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00063.json",
            "crime": "Implicit intent(view a web page, make a phone call, etc.)",
            "label": [
                "control"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/Intent;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String; Landroid/net/Uri;)V"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/Intent;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String; Landroid/net/Uri;)V"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/y; a (Lcom/google/android/gms/internal/ek; Ljava/util/Map;)V": {
                        "first": [
                            "invoke-static",
                            "v9",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 09 00",
                        "second": [
                            "invoke-direct",
                            "v10",
                            "v0",
                            "v9",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String; Landroid/net/Uri;)V"
                        ],
                        "second_hex": "70 30 7f 00 0a 09"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/dm; a (Landroid/content/pm/PackageManager; Ljava/lang/String;)Landroid/content/pm/ResolveInfo;": {
                        "first": [
                            "invoke-static",
                            "v4",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 04 00",
                        "second": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "v2",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String; Landroid/net/Uri;)V"
                        ],
                        "second_hex": "70 30 7f 00 10 02"
                    }
                },
                {
                    "Lcom/pro/lib/a/e; onClick (Landroid/content/DialogInterface; I)V": {
                        "first": [
                            "invoke-static",
                            "v2",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 02 00",
                        "second": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "v2",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String; Landroid/net/Uri;)V"
                        ],
                        "second_hex": "70 30 7f 00 10 02"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/google/android/gms/internal/y; a (Lcom/google/android/gms/internal/ek; Ljava/util/Map;)V": {
                        "first": [
                            "invoke-static",
                            "v9",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 09 00",
                        "second": [
                            "invoke-direct",
                            "v10",
                            "v0",
                            "v9",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String; Landroid/net/Uri;)V"
                        ],
                        "second_hex": "70 30 7f 00 0a 09"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/dm; a (Landroid/content/pm/PackageManager; Ljava/lang/String;)Landroid/content/pm/ResolveInfo;": {
                        "first": [
                            "invoke-static",
                            "v4",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 04 00",
                        "second": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "v2",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String; Landroid/net/Uri;)V"
                        ],
                        "second_hex": "70 30 7f 00 10 02"
                    }
                },
                {
                    "Lcom/pro/lib/a/e; onClick (Landroid/content/DialogInterface; I)V": {
                        "first": [
                            "invoke-static",
                            "v2",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 02 00",
                        "second": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "v2",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String; Landroid/net/Uri;)V"
                        ],
                        "second_hex": "70 30 7f 00 10 02"
                    }
                }
            ]
        },
        {
            "rule": "00118.json",
            "crime": "Check if the content of SMS contains given string",
            "label": [
                "sms",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/String;",
                    "method": "contains",
                    "descriptor": "(Ljava/lang/CharSequence;)Z"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00049.json",
            "crime": "Query the phone number from SMS sender",
            "label": [
                "sms",
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00185.json",
            "crime": "Start capturing camera preview frames to the screen",
            "label": [
                "camera"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "startPreview",
                    "descriptor": "()V"
                },
                {
                    "class": "Ljava/lang/Object;",
                    "method": "<init>",
                    "descriptor": "()V"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "startPreview",
                    "descriptor": "()V"
                },
                {
                    "class": "Ljava/lang/Object;",
                    "method": "<init>",
                    "descriptor": "()V"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00012.json",
            "crime": "Read data and put it into a buffer stream",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileInputStream;",
                    "method": "<init>",
                    "descriptor": "(Ljava/io/File;)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00076.json",
            "crime": "Get the current WiFi information and put it into JSON",
            "label": [
                "collection",
                "wifi"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00158.json",
            "crime": "Connect to a URL and send sensitive data got from resolver",
            "label": [
                "privacy",
                "connection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00065.json",
            "crime": "Get the country code of the SIM card provider",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00156.json",
            "crime": "Acquire lock on Power Manager ",
            "label": [
                "lock",
                "power manager"
            ],
            "score": 1,
            "weight": 0,
            "confidence": "0%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00034.json",
            "crime": "Query the current data network type",
            "label": [
                "collection",
                "network"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                },
                {
                    "class": "Landroid/telephony/TelephonyManager;",
                    "method": "getNetworkType",
                    "descriptor": "()I"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                },
                {
                    "class": "Landroid/telephony/TelephonyManager;",
                    "method": "getNetworkType",
                    "descriptor": "()I"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/dm; <init> (Landroid/content/Context;)V": {
                        "first": [
                            "invoke-virtual",
                            "v10",
                            "v2",
                            "Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;"
                        ],
                        "first_hex": "6e 20 71 00 2a 00",
                        "second": [
                            "invoke-virtual",
                            "v2",
                            "Landroid/telephony/TelephonyManager;->getNetworkType()I"
                        ],
                        "second_hex": "6e 10 57 0c 02 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/google/android/gms/internal/dm; <init> (Landroid/content/Context;)V": {
                        "first": [
                            "invoke-virtual",
                            "v10",
                            "v2",
                            "Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;"
                        ],
                        "first_hex": "6e 20 71 00 2a 00",
                        "second": [
                            "invoke-virtual",
                            "v2",
                            "Landroid/telephony/TelephonyManager;->getNetworkType()I"
                        ],
                        "second_hex": "6e 10 57 0c 02 00"
                    }
                }
            ]
        },
        {
            "rule": "00046.json",
            "crime": "Method reflection",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getDeclaredMethod",
                    "descriptor": "(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                },
                {
                    "class": "Ljava/lang/reflect/Method;",
                    "method": "invoke",
                    "descriptor": "(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getDeclaredMethod",
                    "descriptor": "(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                },
                {
                    "class": "Ljava/lang/reflect/Method;",
                    "method": "invoke",
                    "descriptor": "(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                }
            ],
            "sequence": [
                {
                    "Landroid/support/v4/view/ViewPager; setChildrenDrawingOrderEnabledCompat (Z)V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "v2",
                            "Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "first_hex": "6e 30 d3 25 10 02",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v5",
                            "v1",
                            "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                        ],
                        "second_hex": "6e 30 a5 26 50 01"
                    }
                }
            ],
            "register": [
                {
                    "Landroid/support/v4/view/ViewPager; setChildrenDrawingOrderEnabledCompat (Z)V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "v2",
                            "Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "first_hex": "6e 30 d3 25 10 02",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v5",
                            "v1",
                            "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                        ],
                        "second_hex": "6e 30 a5 26 50 01"
                    }
                }
            ]
        },
        {
            "rule": "00071.json",
            "crime": "Write the ISO country code of the current network operator into a file",
            "label": [
                "collection",
                "command",
                "network",
                "file"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write",
                    "descriptor": "([B)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00127.json",
            "crime": "Monitor the broadcast action events (BOOT_COMPLETED, etc)",
            "label": [
                "command"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Intent;",
                    "method": "getAction",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00062.json",
            "crime": "Query WiFi information and WiFi Mac Address",
            "label": [
                "wifi",
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00211.json",
            "crime": "Open an URL in Wevbiew",
            "label": [],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00167.json",
            "crime": "Use accessibility service to perform action getting root in active window",
            "label": [
                "accessibility service"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00106.json",
            "crime": "Get the currently formatted WiFi IP address",
            "label": [
                "collection",
                "wifi"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00199.json",
            "crime": "Stop recording and release recording resources",
            "label": [
                "record"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00077.json",
            "crime": "Read sensitive data(SMS, CALLLOG, etc)",
            "label": [
                "collection",
                "sms",
                "calllog",
                "calendar"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getContentResolver",
                    "descriptor": "()Landroid/content/ContentResolver;"
                },
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Landroid/content/ContentResolver;",
                    "class": "Landroid/content/Context;",
                    "method": "getContentResolver"
                },
                {
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;",
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query"
                }
            ],
            "sequence": [
                {
                    "Ljp/co/cyberagent/android/gpuimage/e; a ()I": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;"
                        ],
                        "first_hex": "6e 10 68 00 00 00",
                        "second": [
                            "invoke-virtual/range",
                            "v0",
                            "v1",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "second_hex": "74 06 57 00 00 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; a (Landroid/content/Context; Landroid/net/Uri; Ljava/lang/String; [Ljava/lang/String;)Ljava/lang/String;": {
                        "first": [
                            "invoke-virtual",
                            "v7",
                            "Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;"
                        ],
                        "first_hex": "6e 10 68 00 07 00",
                        "second": [
                            "invoke-virtual/range",
                            "v0",
                            "v1",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "second_hex": "74 06 57 00 00 00"
                    }
                },
                {
                    "Landroid/support/v7/widget/e; a (Landroid/app/SearchableInfo; Ljava/lang/String; I)Landroid/database/Cursor;": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;"
                        ],
                        "first_hex": "6e 10 68 00 00 00",
                        "second": [
                            "invoke-virtual/range",
                            "v0",
                            "v1",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "second_hex": "74 06 57 00 00 00"
                    }
                }
            ],
            "register": [
                {
                    "Ljp/co/cyberagent/android/gpuimage/e; a ()I": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;"
                        ],
                        "first_hex": "6e 10 68 00 00 00",
                        "second": [
                            "invoke-virtual/range",
                            "v0",
                            "v1",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "second_hex": "74 06 57 00 00 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; a (Landroid/content/Context; Landroid/net/Uri; Ljava/lang/String; [Ljava/lang/String;)Ljava/lang/String;": {
                        "first": [
                            "invoke-virtual",
                            "v7",
                            "Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;"
                        ],
                        "first_hex": "6e 10 68 00 07 00",
                        "second": [
                            "invoke-virtual/range",
                            "v0",
                            "v1",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "second_hex": "74 06 57 00 00 00"
                    }
                },
                {
                    "Landroid/support/v7/widget/e; a (Landroid/app/SearchableInfo; Ljava/lang/String; I)Landroid/database/Cursor;": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;"
                        ],
                        "first_hex": "6e 10 68 00 00 00",
                        "second": [
                            "invoke-virtual/range",
                            "v0",
                            "v1",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "second_hex": "74 06 57 00 00 00"
                    }
                }
            ]
        },
        {
            "rule": "00192.json",
            "crime": "Get messages in the SMS inbox",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndexOrThrow",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;",
                    "match_keywords": [
                        "sms/inbox"
                    ]
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndexOrThrow",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; a (Landroid/content/Context; Landroid/net/Uri;)Ljava/lang/String;": {
                        "first": [
                            "invoke-static",
                            "v2",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 02 00",
                        "second": [
                            "invoke-static",
                            "v6",
                            "v7",
                            "v0",
                            "v0",
                            "Lcom/pro/lib/libreriafotografia/b;->a(Landroid/content/Context; Landroid/net/Uri; Ljava/lang/String; [Ljava/lang/String;)Ljava/lang/String;"
                        ],
                        "second_hex": "71 40 24 23 76 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00116.json",
            "crime": "Get the current WiFi MAC address and put it into JSON",
            "label": [
                "wifi",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00114.json",
            "crime": "Create a secure socket connection to the proxy address",
            "label": [
                "network",
                "command"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00210.json",
            "crime": "Copy pixels from the latest rendered image into a Bitmap",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/graphics/Bitmap;",
                    "method": "copyPixelsFromBuffer",
                    "descriptor": "(Ljava/nio/Buffer;)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00103.json",
            "crime": "Check the active network type",
            "label": [
                "network"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/ConnectivityManager;",
                    "method": "getActiveNetworkInfo",
                    "descriptor": "()Landroid/net/NetworkInfo;"
                },
                {
                    "class": "Ljava/lang/Object;",
                    "method": "equals",
                    "descriptor": "(Ljava/lang/Object;)Z"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Landroid/net/NetworkInfo;",
                    "class": "Landroid/net/ConnectivityManager;",
                    "method": "getActiveNetworkInfo"
                },
                {
                    "descriptor": "(Ljava/lang/Object;)Z",
                    "class": "Ljava/lang/Object;",
                    "method": "equals"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00124.json",
            "crime": "Check the current active network type",
            "label": [
                "network"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Object;",
                    "method": "equals",
                    "descriptor": "(Ljava/lang/Object;)Z"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00081.json",
            "crime": "Get declared method from given method name",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "<init>",
                    "descriptor": "()V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00204.json",
            "crime": "Get the default ringtone",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00187.json",
            "crime": "Query a URI and check the result",
            "label": [
                "collection",
                "sms",
                "calllog",
                "calendar"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "moveToNext",
                    "descriptor": "()Z"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "moveToNext",
                    "descriptor": "()Z"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00184.json",
            "crime": "Set camera preview texture",
            "label": [
                "camera"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Object;",
                    "method": "<init>",
                    "descriptor": "()V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00122.json",
            "crime": "Check if the sender address of SMS contains the given string",
            "label": [
                "sms",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/String;",
                    "method": "contains",
                    "descriptor": "(Ljava/lang/CharSequence;)Z"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00008.json",
            "crime": "Check if successfully sending out SMS",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Boolean;",
                    "method": "valueOf",
                    "descriptor": "(Z)Ljava/lang/Boolean;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00175.json",
            "crime": "Get notification manager and cancel notifications ",
            "label": [
                "notification"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00135.json",
            "crime": "Get the current WiFi id and put it into JSON.",
            "label": [
                "wifi",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00025.json",
            "crime": "Monitor the general action to be performed",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Intent;",
                    "method": "getAction",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Ljava/lang/String;",
                    "method": "equals",
                    "descriptor": "(Ljava/lang/Object;)Z"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/Intent;",
                    "method": "getAction",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Ljava/lang/String;",
                    "method": "equals",
                    "descriptor": "(Ljava/lang/Object;)Z"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/eb; onReceive (Landroid/content/Context; Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual",
                            "v4",
                            "Landroid/content/Intent;->getAction()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 83 00 04 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Ljava/lang/String;->equals(Ljava/lang/Object;)Z"
                        ],
                        "second_hex": "6e 20 3e 26 10 00"
                    }
                },
                {
                    "Lcom/google/b/a/a/u; onReceive (Landroid/content/Context; Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual",
                            "v4",
                            "Landroid/content/Intent;->getAction()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 83 00 04 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Ljava/lang/String;->equals(Ljava/lang/Object;)Z"
                        ],
                        "second_hex": "6e 20 3e 26 01 00"
                    }
                },
                {
                    "Lcom/b/a/v; onReceive (Landroid/content/Context; Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual",
                            "v5",
                            "Landroid/content/Intent;->getAction()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 83 00 05 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Ljava/lang/String;->equals(Ljava/lang/Object;)Z"
                        ],
                        "second_hex": "6e 20 3e 26 01 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/google/android/gms/internal/eb; onReceive (Landroid/content/Context; Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual",
                            "v4",
                            "Landroid/content/Intent;->getAction()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 83 00 04 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Ljava/lang/String;->equals(Ljava/lang/Object;)Z"
                        ],
                        "second_hex": "6e 20 3e 26 10 00"
                    }
                },
                {
                    "Lcom/google/b/a/a/u; onReceive (Landroid/content/Context; Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual",
                            "v4",
                            "Landroid/content/Intent;->getAction()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 83 00 04 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Ljava/lang/String;->equals(Ljava/lang/Object;)Z"
                        ],
                        "second_hex": "6e 20 3e 26 01 00"
                    }
                },
                {
                    "Lcom/b/a/v; onReceive (Landroid/content/Context; Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual",
                            "v5",
                            "Landroid/content/Intent;->getAction()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 83 00 05 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Ljava/lang/String;->equals(Ljava/lang/Object;)Z"
                        ],
                        "second_hex": "6e 20 3e 26 01 00"
                    }
                }
            ]
        },
        {
            "rule": "00094.json",
            "crime": "Connect to a URL and read data from it",
            "label": [
                "command",
                "network"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/net/URL;",
                    "method": "openConnection",
                    "descriptor": "()Ljava/net/URLConnection;"
                },
                {
                    "class": "Ljava/io/InputStream;",
                    "method": "read",
                    "descriptor": "([B)I"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Ljava/net/URLConnection;",
                    "class": "Ljava/net/URL;",
                    "method": "openConnection"
                },
                {
                    "descriptor": "([B)I",
                    "class": "Ljava/io/InputStream;",
                    "method": "read"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00010.json",
            "crime": "Read sensitive data(SMS, CALLLOG) and put it into JSON object",
            "label": [
                "sms",
                "calllog",
                "collection"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00074.json",
            "crime": "Get IMSI and the ISO country code",
            "label": [
                "collection",
                "telephony"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00053.json",
            "crime": "Monitor data identified by a given content URI changes(SMS, MMS, etc.)",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00203.json",
            "crime": "Put a phone number into an intent",
            "label": [
                "control"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/Intent;",
                    "method": "setData",
                    "descriptor": "(Landroid/net/Uri;)Landroid/content/Intent;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/Intent;",
                    "method": "setData",
                    "descriptor": "(Landroid/net/Uri;)Landroid/content/Intent;",
                    "match_keywords": [
                        "tel:"
                    ]
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonDiverCaraFotoStudio (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizBanderas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal5 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosFun (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosAmigos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionCollageOpcion (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosSanValentin (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal4 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLocalCars (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLocalChistes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal1 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesDosTres (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionIlusionesOpticas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; e ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosUno (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcoFotosFutbolDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveFunMontages2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionIlusionesOpticas2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosDisfraces (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosIncreibles2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPhotoCollageEditor2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizGeografia (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFunLoveFrames (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonLoveTesterMatchCalculator (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveFun2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionOldMontajes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosInf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoMontajesBillboard (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPersonalPostCards (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/bl; a (Landroid/content/Context; Lcom/google/android/gms/internal/bn; Lcom/google/android/gms/internal/bz;)Z": {
                        "first": [
                            "invoke-static",
                            "v3",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 03 00",
                        "second": [
                            "invoke-virtual",
                            "v2",
                            "v3",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 32 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonTourismSimulator (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; b ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/ge; c (Ljava/lang/String;)Landroid/content/Intent;": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 01 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionTarjetas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonFunPhotoCollageStudio (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosSV3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonBillboardDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesEsp (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; b ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionYourPersonalLovePostCardAPP (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFraProf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesEsp2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal9 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFrasesAmistad2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizFootballMund (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetasAmor2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal10 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveTest (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFraAmis (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosIncreibles (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizCoches (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFotosDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPhotoCollageEditor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetasAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizFutbol (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonFunBackgroundChanger (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonMagicCamera (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoMontajesSanValen2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosFutbol (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoWarp (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal7 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesFunGentleman (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFramesAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; e ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal6 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonCollageMaker (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFraProf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosKids3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosInf2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFunnyFaceYou (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonPIP2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionTarjetasAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFraAmis (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizLocal3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonRealLovePhotoFrame (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesBrasil (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizBrasil (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00144.json",
            "crime": "Write SIM card serial number into a file",
            "label": [
                "collection",
                "telephony",
                "file",
                "command"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write",
                    "descriptor": "([B)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00090.json",
            "crime": "Set recroded audio/video file format",
            "label": [
                "record"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00102.json",
            "crime": "Set the phone speaker on",
            "label": [
                "command"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00142.json",
            "crime": "Get calendar information",
            "label": [
                "collection",
                "calendar"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "append",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/StringBuilder;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00169.json",
            "crime": "Use accessibility service to perform global action getting node info by View Id",
            "label": [
                "accessibility service"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00128.json",
            "crime": "Query user account information",
            "label": [
                "collection",
                "account"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00159.json",
            "crime": "Use accessibility service to perform action getting node info by text",
            "label": [
                "accessibility service"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00019.json",
            "crime": "Find a method from given class name, usually for reflection",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Object;",
                    "method": "getClass",
                    "descriptor": "()Ljava/lang/Class;"
                },
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getMethod",
                    "descriptor": "(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/lang/Object;",
                    "method": "getClass",
                    "descriptor": "()Ljava/lang/Class;"
                },
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getMethod",
                    "descriptor": "(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/kp; a (Ljava/lang/String; Ljava/lang/Object; Ljava/lang/StringBuffer; Ljava/lang/StringBuffer;)V": {
                        "first": [
                            "invoke-virtual",
                            "v12",
                            "Ljava/lang/Object;->getClass()Ljava/lang/Class;"
                        ],
                        "first_hex": "6e 10 25 26 0c 00",
                        "second": [
                            "invoke-virtual",
                            "v5",
                            "v0",
                            "v8",
                            "Ljava/lang/Class;->getMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "second_hex": "6e 30 d6 25 05 08"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/fb; b (Lcom/google/android/gms/internal/fb$a;)Ljava/lang/Object;": {
                        "first": [
                            "invoke-virtual",
                            "v4",
                            "Ljava/lang/Object;->getClass()Ljava/lang/Class;"
                        ],
                        "first_hex": "6e 10 25 26 04 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "v2",
                            "Ljava/lang/Class;->getMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "second_hex": "6e 30 d6 25 01 02"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/google/android/gms/internal/kp; a (Ljava/lang/String; Ljava/lang/Object; Ljava/lang/StringBuffer; Ljava/lang/StringBuffer;)V": {
                        "first": [
                            "invoke-virtual",
                            "v12",
                            "Ljava/lang/Object;->getClass()Ljava/lang/Class;"
                        ],
                        "first_hex": "6e 10 25 26 0c 00",
                        "second": [
                            "invoke-virtual",
                            "v5",
                            "v0",
                            "v8",
                            "Ljava/lang/Class;->getMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "second_hex": "6e 30 d6 25 05 08"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/fb; b (Lcom/google/android/gms/internal/fb$a;)Ljava/lang/Object;": {
                        "first": [
                            "invoke-virtual",
                            "v4",
                            "Ljava/lang/Object;->getClass()Ljava/lang/Class;"
                        ],
                        "first_hex": "6e 10 25 26 04 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "v2",
                            "Ljava/lang/Class;->getMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "second_hex": "6e 30 d6 25 01 02"
                    }
                }
            ]
        },
        {
            "rule": "00018.json",
            "crime": "Get JSON object prepared and fill in location info",
            "label": [
                "location",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "<init>",
                    "descriptor": "()V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00112.json",
            "crime": "Get the date of the calendar event",
            "label": [
                "collection",
                "calendar"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00068.json",
            "crime": "Executes the specified string Linux command",
            "label": [
                "control"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00134.json",
            "crime": "Get the current WiFi IP address",
            "label": [
                "wifi",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00113.json",
            "crime": "Get location and put it into JSON",
            "label": [
                "collection",
                "location"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00147.json",
            "crime": "Get the time of current location",
            "label": [
                "collection",
                "location"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/location/Location;",
                    "method": "getTime",
                    "descriptor": "()J"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00079.json",
            "crime": "Hide the current app's icon",
            "label": [
                "evasion"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getPackageManager",
                    "descriptor": "()Landroid/content/pm/PackageManager;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00186.json",
            "crime": "Control camera to take picture",
            "label": [
                "camera"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Object;",
                    "method": "<init>",
                    "descriptor": "()V"
                },
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "takePicture",
                    "descriptor": "(Landroid/hardware/Camera$ShutterCallback; Landroid/hardware/Camera$PictureCallback; Landroid/hardware/Camera$PictureCallback;)V"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/lang/Object;",
                    "method": "<init>",
                    "descriptor": "()V"
                },
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "takePicture",
                    "descriptor": "(Landroid/hardware/Camera$ShutterCallback; Landroid/hardware/Camera$PictureCallback; Landroid/hardware/Camera$PictureCallback;)V"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00050.json",
            "crime": "Query the SMS service centre timestamp",
            "label": [
                "sms",
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00209.json",
            "crime": "Get pixels from the latest rendered image",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00149.json",
            "crime": "Unpack an asset, possibly decrypt it and load it as DEX",
            "label": [
                "packer"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ldalvik/system/DexClassLoader;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Ljava/lang/ClassLoader;)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00011.json",
            "crime": "Query data from URI (SMS, CALLLOGS)",
            "label": [
                "sms",
                "calllog",
                "collection"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; a (Landroid/content/Context; Landroid/net/Uri;)Ljava/lang/String;": {
                        "first": [
                            "invoke-static",
                            "v2",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 02 00",
                        "second": [
                            "invoke-static",
                            "v6",
                            "v7",
                            "v0",
                            "v0",
                            "Lcom/pro/lib/libreriafotografia/b;->a(Landroid/content/Context; Landroid/net/Uri; Ljava/lang/String; [Ljava/lang/String;)Ljava/lang/String;"
                        ],
                        "second_hex": "71 40 24 23 76 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; a (Landroid/content/Context; Landroid/net/Uri;)Ljava/lang/String;": {
                        "first": [
                            "invoke-static",
                            "v2",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 02 00",
                        "second": [
                            "invoke-static",
                            "v6",
                            "v7",
                            "v0",
                            "v0",
                            "Lcom/pro/lib/libreriafotografia/b;->a(Landroid/content/Context; Landroid/net/Uri; Ljava/lang/String; [Ljava/lang/String;)Ljava/lang/String;"
                        ],
                        "second_hex": "71 40 24 23 76 00"
                    }
                }
            ]
        },
        {
            "rule": "00044.json",
            "crime": "Query the last time this package's activity was used",
            "label": [
                "collection",
                "reflection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00024.json",
            "crime": "Write file after Base64 decoding",
            "label": [
                "reflection",
                "file"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write",
                    "descriptor": "([B)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00030.json",
            "crime": "Connect to the remote server through the given URL",
            "label": [
                "network"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/net/URL;",
                    "method": "openConnection",
                    "descriptor": "()Ljava/net/URLConnection;"
                },
                {
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "connect",
                    "descriptor": "()V"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/net/URL;",
                    "method": "openConnection",
                    "descriptor": "()Ljava/net/URLConnection;"
                },
                {
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "connect",
                    "descriptor": "()V"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/ez; a (Landroid/content/Context; Ljava/lang/String; Ljava/lang/String;)Landroid/webkit/WebResourceResponse;": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->connect()V"
                        ],
                        "second_hex": "6e 10 b0 26 00 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/google/android/gms/internal/ez; a (Landroid/content/Context; Ljava/lang/String; Ljava/lang/String;)Landroid/webkit/WebResourceResponse;": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->connect()V"
                        ],
                        "second_hex": "6e 10 b0 26 00 00"
                    }
                }
            ]
        },
        {
            "rule": "00193.json",
            "crime": "Send a SMS message",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00133.json",
            "crime": "Start recording",
            "label": [
                "record",
                "command"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00163.json",
            "crime": "Create new Socket and connecting to it",
            "label": [
                "socket"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00188.json",
            "crime": "Get the address of a SMS message",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;",
                    "match_keywords": [
                        "sms"
                    ]
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I",
                    "match_keywords": [
                        "address"
                    ]
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; onActivityResult (I I Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual/range",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "v6",
                            "v7",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "first_hex": "74 06 57 00 02 00",
                        "second": [
                            "invoke-interface",
                            "v3",
                            "v0",
                            "Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I"
                        ],
                        "second_hex": "72 20 d9 00 03 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00056.json",
            "crime": "Modify voice volume",
            "label": [
                "control"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00091.json",
            "crime": "Retrieve data from broadcast",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Intent;",
                    "method": "getExtras",
                    "descriptor": "()Landroid/os/Bundle;"
                },
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Landroid/os/Bundle;",
                    "class": "Landroid/content/Intent;",
                    "method": "getExtras"
                },
                {
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;",
                    "class": "Landroid/os/Bundle;",
                    "method": "getString"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/ligreriagaleriafolderpicasso/MainLibreriaGaleriaFolderPicassoFullScreen; onCreate (Landroid/os/Bundle;)V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/content/Intent;->getExtras()Landroid/os/Bundle;"
                        ],
                        "first_hex": "6e 10 87 00 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;"
                        ],
                        "second_hex": "6e 20 21 02 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriagraficos/renovado/LibreriaEfectosGraficosRenovado; onCreate (Landroid/os/Bundle;)V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/content/Intent;->getExtras()Landroid/os/Bundle;"
                        ],
                        "first_hex": "6e 10 87 00 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;"
                        ],
                        "second_hex": "6e 20 21 02 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; onActivityResult (I I Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual",
                            "v15",
                            "Landroid/content/Intent;->getExtras()Landroid/os/Bundle;"
                        ],
                        "first_hex": "6e 10 87 00 0f 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v2",
                            "Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;"
                        ],
                        "second_hex": "6e 20 21 02 21 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/pro/lib/ligreriagaleriafolderpicasso/MainLibreriaGaleriaFolderPicassoFullScreen; onCreate (Landroid/os/Bundle;)V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/content/Intent;->getExtras()Landroid/os/Bundle;"
                        ],
                        "first_hex": "6e 10 87 00 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;"
                        ],
                        "second_hex": "6e 20 21 02 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriagraficos/renovado/LibreriaEfectosGraficosRenovado; onCreate (Landroid/os/Bundle;)V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/content/Intent;->getExtras()Landroid/os/Bundle;"
                        ],
                        "first_hex": "6e 10 87 00 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;"
                        ],
                        "second_hex": "6e 20 21 02 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; onActivityResult (I I Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual",
                            "v15",
                            "Landroid/content/Intent;->getExtras()Landroid/os/Bundle;"
                        ],
                        "first_hex": "6e 10 87 00 0f 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v2",
                            "Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;"
                        ],
                        "second_hex": "6e 20 21 02 21 00"
                    }
                }
            ]
        },
        {
            "rule": "00174.json",
            "crime": "Get all accounts by type and put them in a JSON object",
            "label": [
                "accounts",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00101.json",
            "crime": "Initialize recorder",
            "label": [
                "record"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00115.json",
            "crime": "Get last known location of the device",
            "label": [
                "collection",
                "location"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/location/Location;",
                    "method": "getLongitude",
                    "descriptor": "()D"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00047.json",
            "crime": "Query the local IP address",
            "label": [
                "network",
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00155.json",
            "crime": "Execute commands on shell using DataOutputStream object",
            "label": [
                "exec",
                "command"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00130.json",
            "crime": "Get the current WIFI information",
            "label": [
                "wifi",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00177.json",
            "crime": "Check if permission is granted and request it",
            "label": [
                "permission"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00058.json",
            "crime": "Connect to the specific WIFI network",
            "label": [
                "wifi",
                "control"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00001.json",
            "crime": "Initialize bitmap object and compress data (e.g. JPEG) into bitmap object",
            "label": [
                "camera"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/graphics/BitmapFactory;",
                    "method": "decodeByteArray",
                    "descriptor": "([B I I)Landroid/graphics/Bitmap;"
                },
                {
                    "class": "Landroid/graphics/Bitmap;",
                    "method": "compress",
                    "descriptor": "(Landroid/graphics/Bitmap$CompressFormat; I Ljava/io/OutputStream;)Z"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/graphics/BitmapFactory;",
                    "method": "decodeByteArray",
                    "descriptor": "([B I I)Landroid/graphics/Bitmap;"
                },
                {
                    "class": "Landroid/graphics/Bitmap;",
                    "method": "compress",
                    "descriptor": "(Landroid/graphics/Bitmap$CompressFormat; I Ljava/io/OutputStream;)Z"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00069.json",
            "crime": "Run shell script programmably",
            "label": [
                "control"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00060.json",
            "crime": "Query the network operator name",
            "label": [
                "network",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Integer;",
                    "method": "valueOf",
                    "descriptor": "(I)Ljava/lang/Integer;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00200.json",
            "crime": "Query data from the contact list",
            "label": [
                "collection",
                "contact"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;",
                    "match_keywords": [
                        "Phone"
                    ]
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; onActivityResult (I I Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual/range",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "v6",
                            "v7",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "first_hex": "74 06 57 00 02 00",
                        "second": [
                            "invoke-interface",
                            "v3",
                            "v0",
                            "Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I"
                        ],
                        "second_hex": "72 20 d9 00 03 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00119.json",
            "crime": "Write the IMEI number into a file",
            "label": [
                "collection",
                "file",
                "telephony",
                "command"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write",
                    "descriptor": "([B)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00141.json",
            "crime": "Load class from given class name",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "toString",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Ljava/lang/ClassLoader;",
                    "method": "loadClass",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Ljava/lang/String;",
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "toString"
                },
                {
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;",
                    "class": "Ljava/lang/ClassLoader;",
                    "method": "loadClass"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00154.json",
            "crime": "Connect hostname to TCP or UDP socket using KryoNet",
            "label": [
                "socket"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/net/InetAddress;",
                    "method": "getByName",
                    "descriptor": "(Ljava/lang/String;)Ljava/net/InetAddress;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00073.json",
            "crime": "Write the SIM card information into a file",
            "label": [
                "collection",
                "telephony",
                "file"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write",
                    "descriptor": "([B)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00117.json",
            "crime": "Get the IMSI and network operator name",
            "label": [
                "telephony",
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00085.json",
            "crime": "Get the ISO country code and put it into JSON",
            "label": [
                "collection",
                "telephony"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00143.json",
            "crime": "Get external class from given path or file name",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "toString",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00029.json",
            "crime": "Initialize class object dynamically",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Class;",
                    "method": "forName",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00123.json",
            "crime": "Save the response to JSON after connecting to the remote server",
            "label": [
                "network",
                "command"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "connect",
                    "descriptor": "()V"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String;)V"
                }
            ],
            "combination": [
                {
                    "descriptor": "()V",
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "connect"
                },
                {
                    "descriptor": "(Ljava/lang/String;)V",
                    "class": "Lorg/json/JSONObject;",
                    "method": "<init>"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00108.json",
            "crime": "Read the input stream from given URL",
            "label": [
                "network",
                "command"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "getInputStream",
                    "descriptor": "()Ljava/io/InputStream;"
                },
                {
                    "class": "Ljava/io/InputStream;",
                    "method": "read",
                    "descriptor": "([B)I"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Ljava/io/InputStream;",
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "getInputStream"
                },
                {
                    "descriptor": "([B)I",
                    "class": "Ljava/io/InputStream;",
                    "method": "read"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00196.json",
            "crime": "Set the recorded file format and output path",
            "label": [
                "record",
                "file"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00125.json",
            "crime": "Check if the given file path exist",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                },
                {
                    "class": "Ljava/io/File;",
                    "method": "exists",
                    "descriptor": "()Z"
                }
            ],
            "combination": [
                {
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;",
                    "class": "Landroid/os/Bundle;",
                    "method": "getString"
                },
                {
                    "descriptor": "()Z",
                    "class": "Ljava/io/File;",
                    "method": "exists"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00013.json",
            "crime": "Read file and put it into a stream",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/File;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String;)V"
                },
                {
                    "class": "Ljava/io/FileInputStream;",
                    "method": "<init>",
                    "descriptor": "(Ljava/io/File;)V"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/io/File;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String;)V"
                },
                {
                    "class": "Ljava/io/FileInputStream;",
                    "method": "<init>",
                    "descriptor": "(Ljava/io/File;)V"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; a (Ljava/lang/String; I I)Landroid/graphics/Bitmap;": {
                        "first": [
                            "invoke-direct",
                            "v3",
                            "v6",
                            "Ljava/io/File;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 85 25 63 00",
                        "second": [
                            "invoke-direct",
                            "v1",
                            "v3",
                            "Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V"
                        ],
                        "second_hex": "70 20 91 25 31 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; a (Ljava/lang/String; I I)Landroid/graphics/Bitmap;": {
                        "first": [
                            "invoke-direct",
                            "v3",
                            "v6",
                            "Ljava/io/File;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 85 25 63 00",
                        "second": [
                            "invoke-direct",
                            "v1",
                            "v3",
                            "Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V"
                        ],
                        "second_hex": "70 20 91 25 31 00"
                    }
                }
            ]
        },
        {
            "rule": "00080.json",
            "crime": "Save recorded audio/video to a file",
            "label": [
                "record",
                "file"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00037.json",
            "crime": "Send notification",
            "label": [
                "control"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00064.json",
            "crime": "Monitor incoming call status",
            "label": [
                "control"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00015.json",
            "crime": "Put buffer stream (data) to JSON object",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00041.json",
            "crime": "Save recorded audio/video to file",
            "label": [
                "record"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00032.json",
            "crime": "Load external class",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getClassLoader",
                    "descriptor": "()Ljava/lang/ClassLoader;"
                },
                {
                    "class": "Ljava/lang/ClassLoader;",
                    "method": "loadClass",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getClassLoader",
                    "descriptor": "()Ljava/lang/ClassLoader;"
                },
                {
                    "class": "Ljava/lang/ClassLoader;",
                    "method": "loadClass",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00205.json",
            "crime": "Simulate a touch gesture on the device screen",
            "label": [
                "accessibility service",
                "control"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00027.json",
            "crime": "Get specific method from other Dex files",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/ClassLoader;",
                    "method": "loadClass",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;"
                },
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getMethod",
                    "descriptor": "(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/lang/ClassLoader;",
                    "method": "loadClass",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;"
                },
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getMethod",
                    "descriptor": "(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00066.json",
            "crime": "Query the ICCID number",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00055.json",
            "crime": "Query the SMS content and the source of the phone number",
            "label": [
                "sms",
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00036.json",
            "crime": "Get resource file from res/raw directory",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getPackageName",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getPackageName",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                }
            ],
            "sequence": [
                {
                    "Landroid/support/v7/widget/e; a (Ljava/lang/String;)Landroid/graphics/drawable/Drawable;": {
                        "first": [
                            "invoke-virtual",
                            "v3",
                            "Landroid/content/Context;->getPackageName()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 6e 00 03 00",
                        "second": [
                            "invoke-static",
                            "v5",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "second_hex": "71 10 cc 01 05 00"
                    }
                },
                {
                    "Lcom/pro/lib/ligreriagaleriafolderpicasso/j; a ()[Ljava/lang/String;": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/content/Context;->getPackageName()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 6e 00 00 00",
                        "second": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "second_hex": "71 10 cc 01 00 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00166.json",
            "crime": "Get SMS message body and retrieve a string from it (possibly PIN / mTAN)",
            "label": [
                "sms",
                "pin"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00179.json",
            "crime": "Send Location via SMS",
            "label": [
                "location",
                "collection"
            ],
            "score": 1,
            "weight": 0,
            "confidence": "0%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00088.json",
            "crime": "Create a secure socket connection to the given host address",
            "label": [
                "command",
                "network"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00083.json",
            "crime": "Query the IMEI number",
            "label": [
                "collection",
                "telephony"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00003.json",
            "crime": "Put the compressed bitmap data into JSON object",
            "label": [
                "camera"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/graphics/Bitmap;",
                    "method": "compress",
                    "descriptor": "(Landroid/graphics/Bitmap$CompressFormat; I Ljava/io/OutputStream;)Z"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00180.json",
            "crime": "Load native libraries(.so) via System.loadLibrary (60% means caught)",
            "label": [
                "so"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/System;",
                    "method": "loadLibrary",
                    "descriptor": "(Ljava/lang/String;)V"
                },
                {
                    "class": "Ljava/lang/System;",
                    "method": "loadLibrary",
                    "descriptor": "(Ljava/lang/String;)V"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/lang/System;",
                    "method": "loadLibrary",
                    "descriptor": "(Ljava/lang/String;)V"
                },
                {
                    "class": "Ljava/lang/System;",
                    "method": "loadLibrary",
                    "descriptor": "(Ljava/lang/String;)V"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00126.json",
            "crime": "Read sensitive data(SMS, CALLLOG, etc)",
            "label": [
                "collection",
                "sms",
                "calllog",
                "calendar"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Ljava/lang/String;",
                    "method": "toString",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [
                {
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;",
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query"
                },
                {
                    "descriptor": "()Ljava/lang/String;",
                    "class": "Ljava/lang/String;",
                    "method": "toString"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00132.json",
            "crime": "Query The ISO country code",
            "label": [
                "telephony",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00148.json",
            "crime": "Create a socket connection to the given host address",
            "label": [
                "network",
                "command"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00093.json",
            "crime": "Get the content of SMS and forward it to others via SMS",
            "label": [
                "collection",
                "sms",
                "command"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00039.json",
            "crime": "Start a web server",
            "label": [
                "control",
                "network"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00161.json",
            "crime": "Perfom accessibility service action on accessibility node info",
            "label": [
                "accessibility service"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00194.json",
            "crime": "Set the audio source (MIC) and recorded file format",
            "label": [
                "record"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00087.json",
            "crime": "Check the current network type",
            "label": [
                "network"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/NetworkInfo;",
                    "method": "getType",
                    "descriptor": "()I"
                },
                {
                    "class": "Ljava/lang/Object;",
                    "method": "equals",
                    "descriptor": "(Ljava/lang/Object;)Z"
                }
            ],
            "combination": [
                {
                    "descriptor": "()I",
                    "class": "Landroid/net/NetworkInfo;",
                    "method": "getType"
                },
                {
                    "descriptor": "(Ljava/lang/Object;)Z",
                    "class": "Ljava/lang/Object;",
                    "method": "equals"
                }
            ],
            "sequence": [],
            "register": []
        }
    ]
}
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00092.json",
            "crime": "Send broadcast",
            "label": [
                "command"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lcom/pro/lib/a/a;",
                    "method": "getApplicationContext",
                    "descriptor": "()Landroid/content/Context;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00145.json",
            "crime": "Create a socket connection to the proxy address",
            "label": [
                "network",
                "command"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00042.json",
            "crime": "Query WiFi BSSID and scan results",
            "label": [
                "collection",
                "wifi"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00201.json",
            "crime": "Query data from the call log",
            "label": [
                "collection",
                "calllog"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;",
                    "match_keywords": [
                        "call_log"
                    ]
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; onActivityResult (I I Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual/range",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "v6",
                            "v7",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "first_hex": "74 06 57 00 02 00",
                        "second": [
                            "invoke-interface",
                            "v3",
                            "v0",
                            "Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I"
                        ],
                        "second_hex": "72 20 d9 00 03 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00098.json",
            "crime": "Check if the network is connected",
            "label": [
                "network"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/NetworkInfo;",
                    "method": "isConnected",
                    "descriptor": "()Z"
                },
                {
                    "class": "Ljava/lang/Object;",
                    "method": "equals",
                    "descriptor": "(Ljava/lang/Object;)Z"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Z",
                    "class": "Landroid/net/NetworkInfo;",
                    "method": "isConnected"
                },
                {
                    "descriptor": "(Ljava/lang/Object;)Z",
                    "class": "Ljava/lang/Object;",
                    "method": "equals"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00007.json",
            "crime": "Use absolute path of directory for the output media file path",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00009.json",
            "crime": "Put data in cursor to JSON object",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getString",
                    "descriptor": "(I)Ljava/lang/String;"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getString",
                    "descriptor": "(I)Ljava/lang/String;"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00137.json",
            "crime": "Get last known location of the device",
            "label": [
                "location",
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00052.json",
            "crime": "Deletes media specified by a content URI(SMS, CALL_LOG, File, etc.)",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "delete",
                    "descriptor": "(Landroid/net/Uri; Ljava/lang/String; [Ljava/lang/String;)I"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "delete",
                    "descriptor": "(Landroid/net/Uri; Ljava/lang/String; [Ljava/lang/String;)I"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00207.json",
            "crime": "Check if the resource name of the view contains the given string",
            "label": [
                "accessibility service"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/String;",
                    "method": "contains",
                    "descriptor": "(Ljava/lang/CharSequence;)Z"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00190.json",
            "crime": "Query a URI and append the result into a string",
            "label": [
                "collection",
                "sms",
                "calllog",
                "calendar"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "append",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/StringBuilder;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "append",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/StringBuilder;"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; onActivityResult (I I Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual/range",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "v6",
                            "v7",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "first_hex": "74 06 57 00 02 00",
                        "second": [
                            "invoke-virtual",
                            "v12",
                            "Lcom/pro/lib/libreriafotografia/b;->j()V"
                        ],
                        "second_hex": "6e 10 51 23 0c 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00099.json",
            "crime": "Get location of the current GSM and put it into JSON",
            "label": [
                "collection",
                "location"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00176.json",
            "crime": "Send sms to a contact of contact list",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0,
            "confidence": "0%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00075.json",
            "crime": "Get location of the device",
            "label": [
                "collection",
                "location"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00146.json",
            "crime": "Get the network operator name and IMSI",
            "label": [
                "telephony",
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00131.json",
            "crime": "Get location of the current GSM and put it into JSON",
            "label": [
                "collection",
                "location"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00043.json",
            "crime": "Calculate WiFi signal strength",
            "label": [
                "collection",
                "wifi"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00086.json",
            "crime": "Check if the device is in data roaming mode",
            "label": [
                "telephony"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Object;",
                    "method": "equals",
                    "descriptor": "(Ljava/lang/Object;)Z"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00100.json",
            "crime": "Check the network capabilities",
            "label": [
                "collection",
                "network"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Object;",
                    "method": "equals",
                    "descriptor": "(Ljava/lang/Object;)Z"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00189.json",
            "crime": "Get the content of a SMS message",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;",
                    "match_keywords": [
                        "sms"
                    ]
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I",
                    "match_keywords": [
                        "body"
                    ]
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; onActivityResult (I I Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual/range",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "v6",
                            "v7",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "first_hex": "74 06 57 00 02 00",
                        "second": [
                            "invoke-interface",
                            "v3",
                            "v0",
                            "Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I"
                        ],
                        "second_hex": "72 20 d9 00 03 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00195.json",
            "crime": "Set the output path of the recorded file",
            "label": [
                "record",
                "file"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00072.json",
            "crime": "Write HTTP input stream into a file",
            "label": [
                "command",
                "network",
                "file"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "getInputStream",
                    "descriptor": "()Ljava/io/InputStream;"
                },
                {
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write",
                    "descriptor": "([B I I)V"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Ljava/io/InputStream;",
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "getInputStream"
                },
                {
                    "descriptor": "([B I I)V",
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00040.json",
            "crime": "Send SMS",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00097.json",
            "crime": "Get the sender address of the SMS and put it into JSON",
            "label": [
                "collection",
                "sms"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00153.json",
            "crime": "Send binary data over HTTP",
            "label": [
                "http"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [
                "android.permission.INTERNET"
            ],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00202.json",
            "crime": "Make a phone call",
            "label": [
                "control"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Intent;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String;)V"
                },
                {
                    "class": "Landroid/content/Intent;",
                    "method": "setData",
                    "descriptor": "(Landroid/net/Uri;)Landroid/content/Intent;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/Intent;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String;)V",
                    "match_keywords": [
                        "CALL"
                    ]
                },
                {
                    "class": "Landroid/content/Intent;",
                    "method": "setData",
                    "descriptor": "(Landroid/net/Uri;)Landroid/content/Intent;"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/ge; a (Ljava/lang/String;)Landroid/content/Intent;": {
                        "first": [
                            "invoke-direct",
                            "v1",
                            "v2",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 21 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 01 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonDiverCaraFotoStudio (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizBanderas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal5 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosFun (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosAmigos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionCollageOpcion (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosSanValentin (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal4 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLocalCars (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLocalChistes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal1 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesDosTres (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionIlusionesOpticas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; e ()V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosUno (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcoFotosFutbolDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionIlusionesOpticas2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveFunMontages2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosDisfraces (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosIncreibles2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPhotoCollageEditor2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizGeografia (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFunLoveFrames (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonLoveTesterMatchCalculator (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveFun2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionOldMontajes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosInf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoMontajesBillboard (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPersonalPostCards (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonTourismSimulator (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; b ()V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/ge; c (Ljava/lang/String;)Landroid/content/Intent;": {
                        "first": [
                            "invoke-direct",
                            "v1",
                            "v2",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 21 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 01 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionTarjetas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonFunPhotoCollageStudio (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosSV3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonBillboardDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesEsp (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; b ()V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionYourPersonalLovePostCardAPP (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFraProf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesEsp2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal9 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFrasesAmistad2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizFootballMund (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetasAmor2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal10 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveTest (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFraAmis (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosIncreibles (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizCoches (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/ge; b (Ljava/lang/String;)Landroid/content/Intent;": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFotosDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPhotoCollageEditor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetasAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizFutbol (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonFunBackgroundChanger (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonMagicCamera (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoMontajesSanValen2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosFutbol (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoWarp (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal7 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesFunGentleman (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFramesAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; e ()V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal6 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonCollageMaker (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFraProf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosKids3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosInf2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFunnyFaceYou (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonPIP2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionTarjetasAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFraAmis (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizLocal3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonRealLovePhotoFrame (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesBrasil (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 06 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizBrasil (Landroid/view/View;)V": {
                        "first": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 7e 00 10 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00054.json",
            "crime": "Install other APKs from file",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Intent;",
                    "method": "setDataAndType",
                    "descriptor": "(Landroid/net/Uri; Ljava/lang/String;)Landroid/content/Intent;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00183.json",
            "crime": "Get current camera paremeters and change the setting.",
            "label": [
                "camera"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "getParameters",
                    "descriptor": "()Landroid/hardware/Camera$Parameters;"
                },
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "setParameters",
                    "descriptor": "(Landroid/hardware/Camera$Parameters;)V"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "getParameters",
                    "descriptor": "()Landroid/hardware/Camera$Parameters;"
                },
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "setParameters",
                    "descriptor": "(Landroid/hardware/Camera$Parameters;)V"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; o ()V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/hardware/Camera;->getParameters()Landroid/hardware/Camera$Parameters;"
                        ],
                        "first_hex": "6e 10 a1 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Landroid/hardware/Camera;->setParameters(Landroid/hardware/Camera$Parameters;)V"
                        ],
                        "second_hex": "6e 20 a5 01 01 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/a; surfaceChanged (Landroid/view/SurfaceHolder; I I I)V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/hardware/Camera;->getParameters()Landroid/hardware/Camera$Parameters;"
                        ],
                        "first_hex": "6e 10 a1 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Landroid/hardware/Camera;->setParameters(Landroid/hardware/Camera$Parameters;)V"
                        ],
                        "second_hex": "6e 20 a5 01 01 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; o ()V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/hardware/Camera;->getParameters()Landroid/hardware/Camera$Parameters;"
                        ],
                        "first_hex": "6e 10 a1 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Landroid/hardware/Camera;->setParameters(Landroid/hardware/Camera$Parameters;)V"
                        ],
                        "second_hex": "6e 20 a5 01 01 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/a; surfaceChanged (Landroid/view/SurfaceHolder; I I I)V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/hardware/Camera;->getParameters()Landroid/hardware/Camera$Parameters;"
                        ],
                        "first_hex": "6e 10 a1 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Landroid/hardware/Camera;->setParameters(Landroid/hardware/Camera$Parameters;)V"
                        ],
                        "second_hex": "6e 20 a5 01 01 00"
                    }
                }
            ]
        },
        {
            "rule": "00038.json",
            "crime": "Query the phone number",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00197.json",
            "crime": "Set the audio encoder and initialize the recorder",
            "label": [
                "record"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00152.json",
            "crime": "Get data from HTTP and send SMS",
            "label": [
                "command",
                "sms"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [
                "android.permission.INTERNET"
            ],
            "native_api": [
                {
                    "class": "Ljava/net/URL;",
                    "method": "openConnection",
                    "descriptor": "()Ljava/net/URLConnection;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00206.json",
            "crime": "Check if the text of the view contains the given string",
            "label": [
                "accessibility service"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/String;",
                    "method": "contains",
                    "descriptor": "(Ljava/lang/CharSequence;)Z"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00110.json",
            "crime": "Query the ICCID number",
            "label": [
                "collection",
                "telephony"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00208.json",
            "crime": "Capture the contents of the device screen",
            "label": [
                "collection",
                "screen"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00120.json",
            "crime": "Append the sender's address to the string",
            "label": [
                "sms",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "append",
                    "descriptor": "(I)Ljava/lang/StringBuilder;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00014.json",
            "crime": "Read file into a stream and put it into a JSON object",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileInputStream;",
                    "method": "<init>",
                    "descriptor": "(Ljava/io/File;)V"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/io/FileInputStream;",
                    "method": "<init>",
                    "descriptor": "(Ljava/io/File;)V"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00028.json",
            "crime": "Read file from assets directory",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/res/AssetManager;",
                    "method": "open",
                    "descriptor": "(Ljava/lang/String;)Ljava/io/InputStream;"
                },
                {
                    "class": "Ljava/io/InputStream;",
                    "method": "read",
                    "descriptor": "([B)I"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/res/AssetManager;",
                    "method": "open",
                    "descriptor": "(Ljava/lang/String;)Ljava/io/InputStream;"
                },
                {
                    "class": "Ljava/io/InputStream;",
                    "method": "read",
                    "descriptor": "([B)I"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00022.json",
            "crime": "Open a file from given absolute path of the file",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Ljava/io/File;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String;)V"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Ljava/io/File;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String;)V"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00006.json",
            "crime": "Scheduling recording task",
            "label": [
                "record"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00035.json",
            "crime": "Query the list of the installed packages",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getPackageManager",
                    "descriptor": "()Landroid/content/pm/PackageManager;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00070.json",
            "crime": "Get sender's address and send SMS",
            "label": [
                "collection",
                "command",
                "sms"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00151.json",
            "crime": "Send phone number over Internet",
            "label": [
                "phone",
                "privacy"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [
                "android.permission.INTERNET"
            ],
            "native_api": [
                {
                    "class": "Ljava/net/URL;",
                    "method": "openConnection",
                    "descriptor": "()Ljava/net/URLConnection;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00171.json",
            "crime": "Compare network operator with a string",
            "label": [
                "network"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/String;",
                    "method": "equals",
                    "descriptor": "(Ljava/lang/Object;)Z"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00089.json",
            "crime": "Connect to a URL and receive input stream from the server",
            "label": [
                "command",
                "network"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/net/URL;",
                    "method": "openConnection",
                    "descriptor": "()Ljava/net/URLConnection;"
                },
                {
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "getInputStream",
                    "descriptor": "()Ljava/io/InputStream;"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Ljava/net/URLConnection;",
                    "class": "Ljava/net/URL;",
                    "method": "openConnection"
                },
                {
                    "descriptor": "()Ljava/io/InputStream;",
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "getInputStream"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/de; a (Landroid/content/Context; Ljava/lang/String; Ljava/lang/String;)Lcom/google/android/gms/internal/cf;": {
                        "first": [
                            "invoke-virtual",
                            "v2",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 02 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;"
                        ],
                        "second_hex": "6e 10 b5 26 00 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/ez; a (Landroid/content/Context; Ljava/lang/String; Ljava/lang/String;)Landroid/webkit/WebResourceResponse;": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;"
                        ],
                        "second_hex": "6e 10 b5 26 00 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/google/android/gms/internal/de; a (Landroid/content/Context; Ljava/lang/String; Ljava/lang/String;)Lcom/google/android/gms/internal/cf;": {
                        "first": [
                            "invoke-virtual",
                            "v2",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 02 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;"
                        ],
                        "second_hex": "6e 10 b5 26 00 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/ez; a (Landroid/content/Context; Ljava/lang/String; Ljava/lang/String;)Landroid/webkit/WebResourceResponse;": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;"
                        ],
                        "second_hex": "6e 10 b5 26 00 00"
                    }
                }
            ]
        },
        {
            "rule": "00178.json",
            "crime": "Execute Linux commands via ProcessBuilder",
            "label": [
                "command"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00096.json",
            "crime": "Connect to a URL and set request method",
            "label": [
                "command",
                "network"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/net/URL;",
                    "method": "openConnection",
                    "descriptor": "()Ljava/net/URLConnection;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00139.json",
            "crime": "Get the current WiFi id",
            "label": [
                "collection",
                "wifi"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00191.json",
            "crime": "Get messages in the SMS inbox",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;",
                    "match_keywords": [
                        "sms/inbox"
                    ]
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00051.json",
            "crime": "Implicit intent(view a web page, make a phone call, etc.) via setData",
            "label": [
                "control"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/Intent;",
                    "method": "setData",
                    "descriptor": "(Landroid/net/Uri;)Landroid/content/Intent;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/Intent;",
                    "method": "setData",
                    "descriptor": "(Landroid/net/Uri;)Landroid/content/Intent;"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonDiverCaraFotoStudio (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizBanderas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal5 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosFun (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosAmigos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionCollageOpcion (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosSanValentin (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal4 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLocalCars (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLocalChistes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal1 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesDosTres (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionIlusionesOpticas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; e ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosUno (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcoFotosFutbolDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveFunMontages2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionIlusionesOpticas2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosDisfraces (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosIncreibles2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPhotoCollageEditor2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizGeografia (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFunLoveFrames (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonLoveTesterMatchCalculator (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveFun2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionOldMontajes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosInf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoMontajesBillboard (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPersonalPostCards (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/bl; a (Landroid/content/Context; Lcom/google/android/gms/internal/bn; Lcom/google/android/gms/internal/bz;)Z": {
                        "first": [
                            "invoke-static",
                            "v3",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 03 00",
                        "second": [
                            "invoke-virtual",
                            "v2",
                            "v3",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 32 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonTourismSimulator (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; b ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/ge; c (Ljava/lang/String;)Landroid/content/Intent;": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 01 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionTarjetas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonFunPhotoCollageStudio (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosSV3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonBillboardDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesEsp (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; b ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionYourPersonalLovePostCardAPP (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFraProf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesEsp2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal9 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFrasesAmistad2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizFootballMund (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetasAmor2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal10 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveTest (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFraAmis (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosIncreibles (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizCoches (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFotosDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPhotoCollageEditor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetasAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizFutbol (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonFunBackgroundChanger (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonMagicCamera (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoMontajesSanValen2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosFutbol (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoWarp (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal7 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesFunGentleman (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFramesAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; e ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal6 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonCollageMaker (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFraProf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosKids3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosInf2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFunnyFaceYou (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonPIP2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionTarjetasAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFraAmis (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizLocal3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonRealLovePhotoFrame (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesBrasil (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizBrasil (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonDiverCaraFotoStudio (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizBanderas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal5 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosFun (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosAmigos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionCollageOpcion (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosSanValentin (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal4 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLocalCars (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLocalChistes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal1 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesDosTres (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionIlusionesOpticas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; e ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosUno (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcoFotosFutbolDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveFunMontages2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionIlusionesOpticas2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosDisfraces (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosIncreibles2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPhotoCollageEditor2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizGeografia (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFunLoveFrames (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonLoveTesterMatchCalculator (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveFun2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionOldMontajes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosInf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoMontajesBillboard (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPersonalPostCards (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/bl; a (Landroid/content/Context; Lcom/google/android/gms/internal/bn; Lcom/google/android/gms/internal/bz;)Z": {
                        "first": [
                            "invoke-static",
                            "v3",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 03 00",
                        "second": [
                            "invoke-virtual",
                            "v2",
                            "v3",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 32 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonTourismSimulator (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; b ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/ge; c (Ljava/lang/String;)Landroid/content/Intent;": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 01 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionTarjetas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonFunPhotoCollageStudio (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosSV3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonBillboardDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesEsp (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; b ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionYourPersonalLovePostCardAPP (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFraProf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesEsp2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal9 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFrasesAmistad2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizFootballMund (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetasAmor2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal10 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveTest (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFraAmis (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosIncreibles (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizCoches (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFotosDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPhotoCollageEditor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetasAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizFutbol (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonFunBackgroundChanger (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonMagicCamera (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoMontajesSanValen2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosFutbol (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoWarp (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal7 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesFunGentleman (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFramesAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; e ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal6 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonCollageMaker (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFraProf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosKids3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosInf2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFunnyFaceYou (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonPIP2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionTarjetasAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFraAmis (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizLocal3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonRealLovePhotoFrame (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesBrasil (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizBrasil (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                }
            ]
        },
        {
            "rule": "00021.json",
            "crime": "Load additional DEX files dynamically",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Ljava/lang/ClassLoader;",
                    "method": "loadClass",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Ljava/lang/ClassLoader;",
                    "method": "loadClass",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00045.json",
            "crime": "Query the name of currently running application",
            "label": [
                "collection",
                "reflection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00033.json",
            "crime": "Query the IMEI number",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00078.json",
            "crime": "Get the network operator name",
            "label": [
                "collection",
                "telephony"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00026.json",
            "crime": "Method reflection",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getMethod",
                    "descriptor": "(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                },
                {
                    "class": "Ljava/lang/reflect/Method;",
                    "method": "invoke",
                    "descriptor": "(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getMethod",
                    "descriptor": "(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                },
                {
                    "class": "Ljava/lang/reflect/Method;",
                    "method": "invoke",
                    "descriptor": "(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/kp; a (Ljava/lang/String; Ljava/lang/Object; Ljava/lang/StringBuffer; Ljava/lang/StringBuffer;)V": {
                        "first": [
                            "invoke-virtual",
                            "v5",
                            "v0",
                            "v8",
                            "Ljava/lang/Class;->getMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "first_hex": "6e 30 d6 25 05 08",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v12",
                            "v8",
                            "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                        ],
                        "second_hex": "6e 30 a5 26 c0 08"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/fb; b (Lcom/google/android/gms/internal/fb$a;)Ljava/lang/Object;": {
                        "first": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "v2",
                            "Ljava/lang/Class;->getMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "first_hex": "6e 30 d6 25 01 02",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v4",
                            "v1",
                            "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                        ],
                        "second_hex": "6e 30 a5 26 40 01"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/google/android/gms/internal/kp; a (Ljava/lang/String; Ljava/lang/Object; Ljava/lang/StringBuffer; Ljava/lang/StringBuffer;)V": {
                        "first": [
                            "invoke-virtual",
                            "v5",
                            "v0",
                            "v8",
                            "Ljava/lang/Class;->getMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "first_hex": "6e 30 d6 25 05 08",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v12",
                            "v8",
                            "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                        ],
                        "second_hex": "6e 30 a5 26 c0 08"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/fb; b (Lcom/google/android/gms/internal/fb$a;)Ljava/lang/Object;": {
                        "first": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "v2",
                            "Ljava/lang/Class;->getMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "first_hex": "6e 30 d6 25 01 02",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v4",
                            "v1",
                            "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                        ],
                        "second_hex": "6e 30 a5 26 40 01"
                    }
                }
            ]
        },
        {
            "rule": "00136.json",
            "crime": "Stop recording",
            "label": [
                "record",
                "command"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00172.json",
            "crime": "Check Admin permissions to (probably) get them",
            "label": [
                "admin"
            ],
            "score": 1,
            "weight": 0,
            "confidence": "0%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00004.json",
            "crime": "Get filename and put it to JSON object",
            "label": [
                "file",
                "collection"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getName",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getName",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00095.json",
            "crime": "Write the ICCID of device into a file",
            "label": [
                "collection",
                "telephony"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write",
                    "descriptor": "([B)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00017.json",
            "crime": "Get Location of the device and append this info to a string",
            "label": [
                "location",
                "collection"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/location/Location;",
                    "method": "getLatitude",
                    "descriptor": "()D"
                },
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "append",
                    "descriptor": "(D)Ljava/lang/StringBuilder;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/location/Location;",
                    "method": "getLatitude",
                    "descriptor": "()D"
                },
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "append",
                    "descriptor": "(D)Ljava/lang/StringBuilder;"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00140.json",
            "crime": "Write the phone number into a file",
            "label": [
                "collection",
                "telephony",
                "file",
                "command"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write",
                    "descriptor": "([B)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00016.json",
            "crime": "Get location info of the device and put it to JSON object",
            "label": [
                "location",
                "collection"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/location/Location;",
                    "method": "getLongitude",
                    "descriptor": "()D"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/location/Location;",
                    "method": "getLongitude",
                    "descriptor": "()D"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/dg; a (Lcom/google/android/gms/internal/cd; Lcom/google/android/gms/internal/dm; Landroid/location/Location;)Ljava/lang/String;": {
                        "first": [
                            "invoke-static",
                            "v2",
                            "v0",
                            "Lcom/google/android/gms/internal/dg;->a(Ljava/util/HashMap; Landroid/location/Location;)V"
                        ],
                        "first_hex": "71 20 f8 17 02 00",
                        "second": [
                            "invoke-static",
                            "v2",
                            "Lcom/google/android/gms/internal/dz;->a(Ljava/util/Map;)Lorg/json/JSONObject;"
                        ],
                        "second_hex": "71 10 58 18 02 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00061.json",
            "crime": "Return dynamic information about the current Wi-Fi connection",
            "label": [
                "wifi",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Integer;",
                    "method": "valueOf",
                    "descriptor": "(I)Ljava/lang/Integer;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00129.json",
            "crime": "Get the content of SMS",
            "label": [
                "sms",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/String;",
                    "method": "toString",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00165.json",
            "crime": "Get SMS message body and send it through http",
            "label": [
                "sms",
                "http"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00020.json",
            "crime": "Get absolute path of the file and store in string",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "toString",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "toString",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/ligreriagaleriafolderpicasso/j; a ()[Ljava/lang/String;": {
                        "first": [
                            "invoke-virtual",
                            "v8",
                            "Ljava/io/File;->getAbsolutePath()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 8a 25 08 00",
                        "second": [
                            "invoke-virtual",
                            "v7",
                            "Ljava/lang/StringBuilder;->toString()Ljava/lang/String;"
                        ],
                        "second_hex": "6e 10 72 26 07 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/pro/lib/ligreriagaleriafolderpicasso/j; a ()[Ljava/lang/String;": {
                        "first": [
                            "invoke-virtual",
                            "v8",
                            "Ljava/io/File;->getAbsolutePath()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 8a 25 08 00",
                        "second": [
                            "invoke-virtual",
                            "v7",
                            "Ljava/lang/StringBuilder;->toString()Ljava/lang/String;"
                        ],
                        "second_hex": "6e 10 72 26 07 00"
                    }
                }
            ]
        },
        {
            "rule": "00121.json",
            "crime": "Create a directory",
            "label": [
                "file",
                "command"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                },
                {
                    "class": "Ljava/io/File;",
                    "method": "mkdirs",
                    "descriptor": "()Z"
                }
            ],
            "combination": [
                {
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;",
                    "class": "Landroid/os/Bundle;",
                    "method": "getString"
                },
                {
                    "descriptor": "()Z",
                    "class": "Ljava/io/File;",
                    "method": "mkdirs"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00138.json",
            "crime": "Set the audio source (MIC)",
            "label": [
                "record"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00182.json",
            "crime": "Open camera.",
            "label": [
                "camera"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "open",
                    "descriptor": "(I)Landroid/hardware/Camera;"
                },
                {
                    "class": "Ljava/lang/Object;",
                    "method": "<init>",
                    "descriptor": "()V"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "open",
                    "descriptor": "(I)Landroid/hardware/Camera;"
                },
                {
                    "class": "Ljava/lang/Object;",
                    "method": "<init>",
                    "descriptor": "()V"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00057.json",
            "crime": "Return the DHCP-assigned addresses from the last successful DHCP request",
            "label": [
                "network",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "toString",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00150.json",
            "crime": "Send IMSI over Internet",
            "label": [
                "phone"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [
                "android.permission.INTERNET"
            ],
            "native_api": [
                {
                    "class": "Ljava/net/URL;",
                    "method": "openConnection",
                    "descriptor": "()Ljava/net/URLConnection;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00082.json",
            "crime": "Get the current WiFi MAC address",
            "label": [
                "collection",
                "wifi"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00164.json",
            "crime": "Get SMS address and send it through http",
            "label": [
                "sms",
                "http"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00170.json",
            "crime": "Get installed applications and put the list in shared preferences",
            "label": [
                "applications",
                "privacy"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00059.json",
            "crime": "Query the SIM card status",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Integer;",
                    "method": "intValue",
                    "descriptor": "()I"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00105.json",
            "crime": "Append the sender's address to the string",
            "label": [
                "collection",
                "sms"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "append",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/StringBuilder;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00160.json",
            "crime": "Use accessibility service to perform action getting node info by View Id",
            "label": [
                "accessibility service"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00031.json",
            "crime": "Check the list of currently running applications",
            "label": [
                "reflection",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ComponentName;",
                    "method": "getPackageName",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00109.json",
            "crime": "Connect to a URL and get the response code",
            "label": [
                "network",
                "command"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/net/URL;",
                    "method": "openConnection",
                    "descriptor": "()Ljava/net/URLConnection;"
                },
                {
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "getResponseCode",
                    "descriptor": "()I"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Ljava/net/URLConnection;",
                    "class": "Ljava/net/URL;",
                    "method": "openConnection"
                },
                {
                    "descriptor": "()I",
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "getResponseCode"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/de; a (Landroid/content/Context; Ljava/lang/String; Ljava/lang/String;)Lcom/google/android/gms/internal/cf;": {
                        "first": [
                            "invoke-virtual",
                            "v2",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 02 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->getResponseCode()I"
                        ],
                        "second_hex": "6e 10 b6 26 00 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/ef; a ()V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->getResponseCode()I"
                        ],
                        "second_hex": "6e 10 b6 26 00 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/google/android/gms/internal/de; a (Landroid/content/Context; Ljava/lang/String; Ljava/lang/String;)Lcom/google/android/gms/internal/cf;": {
                        "first": [
                            "invoke-virtual",
                            "v2",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 02 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->getResponseCode()I"
                        ],
                        "second_hex": "6e 10 b6 26 00 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/ef; a ()V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->getResponseCode()I"
                        ],
                        "second_hex": "6e 10 b6 26 00 00"
                    }
                }
            ]
        },
        {
            "rule": "00162.json",
            "crime": "Create InetSocketAddress object and connecting to it",
            "label": [
                "socket"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00023.json",
            "crime": "Start another application from current application",
            "label": [
                "reflection",
                "control"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "startActivity",
                    "descriptor": "(Landroid/content/Intent;)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00181.json",
            "crime": "Load native libraries(.so) via System.load (60% means caught)",
            "label": [
                "so"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00067.json",
            "crime": "Query the IMSI number",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00173.json",
            "crime": "Get bounds in screen of an AccessibilityNodeInfo and perform action",
            "label": [
                "accessibility service"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00107.json",
            "crime": "Write the IMSI number into a file",
            "label": [
                "collection",
                "telephony",
                "file",
                "command"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write",
                    "descriptor": "([B)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00168.json",
            "crime": "Use accessibility service to perform global action getting node info by text",
            "label": [
                "accessibility service"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00084.json",
            "crime": "Get the ISO country code and IMSI",
            "label": [
                "collection",
                "telephony"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00111.json",
            "crime": "Get the sender address of the SMS",
            "label": [
                "collection",
                "sms"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/String;",
                    "method": "toString",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00048.json",
            "crime": "Query the SMS contents",
            "label": [
                "sms",
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00198.json",
            "crime": "Initialize the recorder and start recording",
            "label": [
                "record"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00104.json",
            "crime": "Check if the given path is directory",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00002.json",
            "crime": "Open the camera and take picture",
            "label": [
                "camera"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "open",
                    "descriptor": "(I)Landroid/hardware/Camera;"
                },
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "takePicture",
                    "descriptor": "(Landroid/hardware/Camera$ShutterCallback; Landroid/hardware/Camera$PictureCallback; Landroid/hardware/Camera$PictureCallback;)V"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "open",
                    "descriptor": "(I)Landroid/hardware/Camera;"
                },
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "takePicture",
                    "descriptor": "(Landroid/hardware/Camera$ShutterCallback; Landroid/hardware/Camera$PictureCallback; Landroid/hardware/Camera$PictureCallback;)V"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00005.json",
            "crime": "Get absolute path of file and put it to JSON object",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/io/File;",
                    "method": "getAbsolutePath",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00063.json",
            "crime": "Implicit intent(view a web page, make a phone call, etc.)",
            "label": [
                "control"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/Intent;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String; Landroid/net/Uri;)V"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/Intent;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String; Landroid/net/Uri;)V"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/y; a (Lcom/google/android/gms/internal/ek; Ljava/util/Map;)V": {
                        "first": [
                            "invoke-static",
                            "v9",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 09 00",
                        "second": [
                            "invoke-direct",
                            "v10",
                            "v0",
                            "v9",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String; Landroid/net/Uri;)V"
                        ],
                        "second_hex": "70 30 7f 00 0a 09"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/dm; a (Landroid/content/pm/PackageManager; Ljava/lang/String;)Landroid/content/pm/ResolveInfo;": {
                        "first": [
                            "invoke-static",
                            "v4",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 04 00",
                        "second": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "v2",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String; Landroid/net/Uri;)V"
                        ],
                        "second_hex": "70 30 7f 00 10 02"
                    }
                },
                {
                    "Lcom/pro/lib/a/e; onClick (Landroid/content/DialogInterface; I)V": {
                        "first": [
                            "invoke-static",
                            "v2",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 02 00",
                        "second": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "v2",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String; Landroid/net/Uri;)V"
                        ],
                        "second_hex": "70 30 7f 00 10 02"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/google/android/gms/internal/y; a (Lcom/google/android/gms/internal/ek; Ljava/util/Map;)V": {
                        "first": [
                            "invoke-static",
                            "v9",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 09 00",
                        "second": [
                            "invoke-direct",
                            "v10",
                            "v0",
                            "v9",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String; Landroid/net/Uri;)V"
                        ],
                        "second_hex": "70 30 7f 00 0a 09"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/dm; a (Landroid/content/pm/PackageManager; Ljava/lang/String;)Landroid/content/pm/ResolveInfo;": {
                        "first": [
                            "invoke-static",
                            "v4",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 04 00",
                        "second": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "v2",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String; Landroid/net/Uri;)V"
                        ],
                        "second_hex": "70 30 7f 00 10 02"
                    }
                },
                {
                    "Lcom/pro/lib/a/e; onClick (Landroid/content/DialogInterface; I)V": {
                        "first": [
                            "invoke-static",
                            "v2",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 02 00",
                        "second": [
                            "invoke-direct",
                            "v0",
                            "v1",
                            "v2",
                            "Landroid/content/Intent;-><init>(Ljava/lang/String; Landroid/net/Uri;)V"
                        ],
                        "second_hex": "70 30 7f 00 10 02"
                    }
                }
            ]
        },
        {
            "rule": "00118.json",
            "crime": "Check if the content of SMS contains given string",
            "label": [
                "sms",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/String;",
                    "method": "contains",
                    "descriptor": "(Ljava/lang/CharSequence;)Z"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00049.json",
            "crime": "Query the phone number from SMS sender",
            "label": [
                "sms",
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00185.json",
            "crime": "Start capturing camera preview frames to the screen",
            "label": [
                "camera"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "startPreview",
                    "descriptor": "()V"
                },
                {
                    "class": "Ljava/lang/Object;",
                    "method": "<init>",
                    "descriptor": "()V"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "startPreview",
                    "descriptor": "()V"
                },
                {
                    "class": "Ljava/lang/Object;",
                    "method": "<init>",
                    "descriptor": "()V"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00012.json",
            "crime": "Read data and put it into a buffer stream",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileInputStream;",
                    "method": "<init>",
                    "descriptor": "(Ljava/io/File;)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00076.json",
            "crime": "Get the current WiFi information and put it into JSON",
            "label": [
                "collection",
                "wifi"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00158.json",
            "crime": "Connect to a URL and send sensitive data got from resolver",
            "label": [
                "privacy",
                "connection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00065.json",
            "crime": "Get the country code of the SIM card provider",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00156.json",
            "crime": "Acquire lock on Power Manager ",
            "label": [
                "lock",
                "power manager"
            ],
            "score": 1,
            "weight": 0,
            "confidence": "0%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00034.json",
            "crime": "Query the current data network type",
            "label": [
                "collection",
                "network"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                },
                {
                    "class": "Landroid/telephony/TelephonyManager;",
                    "method": "getNetworkType",
                    "descriptor": "()I"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                },
                {
                    "class": "Landroid/telephony/TelephonyManager;",
                    "method": "getNetworkType",
                    "descriptor": "()I"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/dm; <init> (Landroid/content/Context;)V": {
                        "first": [
                            "invoke-virtual",
                            "v10",
                            "v2",
                            "Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;"
                        ],
                        "first_hex": "6e 20 71 00 2a 00",
                        "second": [
                            "invoke-virtual",
                            "v2",
                            "Landroid/telephony/TelephonyManager;->getNetworkType()I"
                        ],
                        "second_hex": "6e 10 57 0c 02 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/google/android/gms/internal/dm; <init> (Landroid/content/Context;)V": {
                        "first": [
                            "invoke-virtual",
                            "v10",
                            "v2",
                            "Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;"
                        ],
                        "first_hex": "6e 20 71 00 2a 00",
                        "second": [
                            "invoke-virtual",
                            "v2",
                            "Landroid/telephony/TelephonyManager;->getNetworkType()I"
                        ],
                        "second_hex": "6e 10 57 0c 02 00"
                    }
                }
            ]
        },
        {
            "rule": "00046.json",
            "crime": "Method reflection",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getDeclaredMethod",
                    "descriptor": "(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                },
                {
                    "class": "Ljava/lang/reflect/Method;",
                    "method": "invoke",
                    "descriptor": "(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getDeclaredMethod",
                    "descriptor": "(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                },
                {
                    "class": "Ljava/lang/reflect/Method;",
                    "method": "invoke",
                    "descriptor": "(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                }
            ],
            "sequence": [
                {
                    "Landroid/support/v4/view/ViewPager; setChildrenDrawingOrderEnabledCompat (Z)V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "v2",
                            "Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "first_hex": "6e 30 d3 25 10 02",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v5",
                            "v1",
                            "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                        ],
                        "second_hex": "6e 30 a5 26 50 01"
                    }
                }
            ],
            "register": [
                {
                    "Landroid/support/v4/view/ViewPager; setChildrenDrawingOrderEnabledCompat (Z)V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "v2",
                            "Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "first_hex": "6e 30 d3 25 10 02",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v5",
                            "v1",
                            "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
                        ],
                        "second_hex": "6e 30 a5 26 50 01"
                    }
                }
            ]
        },
        {
            "rule": "00071.json",
            "crime": "Write the ISO country code of the current network operator into a file",
            "label": [
                "collection",
                "command",
                "network",
                "file"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write",
                    "descriptor": "([B)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00127.json",
            "crime": "Monitor the broadcast action events (BOOT_COMPLETED, etc)",
            "label": [
                "command"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Intent;",
                    "method": "getAction",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00062.json",
            "crime": "Query WiFi information and WiFi Mac Address",
            "label": [
                "wifi",
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00211.json",
            "crime": "Open an URL in Wevbiew",
            "label": [],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00167.json",
            "crime": "Use accessibility service to perform action getting root in active window",
            "label": [
                "accessibility service"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00106.json",
            "crime": "Get the currently formatted WiFi IP address",
            "label": [
                "collection",
                "wifi"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00199.json",
            "crime": "Stop recording and release recording resources",
            "label": [
                "record"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00077.json",
            "crime": "Read sensitive data(SMS, CALLLOG, etc)",
            "label": [
                "collection",
                "sms",
                "calllog",
                "calendar"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getContentResolver",
                    "descriptor": "()Landroid/content/ContentResolver;"
                },
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Landroid/content/ContentResolver;",
                    "class": "Landroid/content/Context;",
                    "method": "getContentResolver"
                },
                {
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;",
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query"
                }
            ],
            "sequence": [
                {
                    "Ljp/co/cyberagent/android/gpuimage/e; a ()I": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;"
                        ],
                        "first_hex": "6e 10 68 00 00 00",
                        "second": [
                            "invoke-virtual/range",
                            "v0",
                            "v1",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "second_hex": "74 06 57 00 00 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; a (Landroid/content/Context; Landroid/net/Uri; Ljava/lang/String; [Ljava/lang/String;)Ljava/lang/String;": {
                        "first": [
                            "invoke-virtual",
                            "v7",
                            "Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;"
                        ],
                        "first_hex": "6e 10 68 00 07 00",
                        "second": [
                            "invoke-virtual/range",
                            "v0",
                            "v1",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "second_hex": "74 06 57 00 00 00"
                    }
                },
                {
                    "Landroid/support/v7/widget/e; a (Landroid/app/SearchableInfo; Ljava/lang/String; I)Landroid/database/Cursor;": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;"
                        ],
                        "first_hex": "6e 10 68 00 00 00",
                        "second": [
                            "invoke-virtual/range",
                            "v0",
                            "v1",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "second_hex": "74 06 57 00 00 00"
                    }
                }
            ],
            "register": [
                {
                    "Ljp/co/cyberagent/android/gpuimage/e; a ()I": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;"
                        ],
                        "first_hex": "6e 10 68 00 00 00",
                        "second": [
                            "invoke-virtual/range",
                            "v0",
                            "v1",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "second_hex": "74 06 57 00 00 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; a (Landroid/content/Context; Landroid/net/Uri; Ljava/lang/String; [Ljava/lang/String;)Ljava/lang/String;": {
                        "first": [
                            "invoke-virtual",
                            "v7",
                            "Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;"
                        ],
                        "first_hex": "6e 10 68 00 07 00",
                        "second": [
                            "invoke-virtual/range",
                            "v0",
                            "v1",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "second_hex": "74 06 57 00 00 00"
                    }
                },
                {
                    "Landroid/support/v7/widget/e; a (Landroid/app/SearchableInfo; Ljava/lang/String; I)Landroid/database/Cursor;": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;"
                        ],
                        "first_hex": "6e 10 68 00 00 00",
                        "second": [
                            "invoke-virtual/range",
                            "v0",
                            "v1",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "second_hex": "74 06 57 00 00 00"
                    }
                }
            ]
        },
        {
            "rule": "00192.json",
            "crime": "Get messages in the SMS inbox",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndexOrThrow",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;",
                    "match_keywords": [
                        "sms/inbox"
                    ]
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndexOrThrow",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; a (Landroid/content/Context; Landroid/net/Uri;)Ljava/lang/String;": {
                        "first": [
                            "invoke-static",
                            "v2",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 02 00",
                        "second": [
                            "invoke-static",
                            "v6",
                            "v7",
                            "v0",
                            "v0",
                            "Lcom/pro/lib/libreriafotografia/b;->a(Landroid/content/Context; Landroid/net/Uri; Ljava/lang/String; [Ljava/lang/String;)Ljava/lang/String;"
                        ],
                        "second_hex": "71 40 24 23 76 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00116.json",
            "crime": "Get the current WiFi MAC address and put it into JSON",
            "label": [
                "wifi",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00114.json",
            "crime": "Create a secure socket connection to the proxy address",
            "label": [
                "network",
                "command"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00210.json",
            "crime": "Copy pixels from the latest rendered image into a Bitmap",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/graphics/Bitmap;",
                    "method": "copyPixelsFromBuffer",
                    "descriptor": "(Ljava/nio/Buffer;)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00103.json",
            "crime": "Check the active network type",
            "label": [
                "network"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/ConnectivityManager;",
                    "method": "getActiveNetworkInfo",
                    "descriptor": "()Landroid/net/NetworkInfo;"
                },
                {
                    "class": "Ljava/lang/Object;",
                    "method": "equals",
                    "descriptor": "(Ljava/lang/Object;)Z"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Landroid/net/NetworkInfo;",
                    "class": "Landroid/net/ConnectivityManager;",
                    "method": "getActiveNetworkInfo"
                },
                {
                    "descriptor": "(Ljava/lang/Object;)Z",
                    "class": "Ljava/lang/Object;",
                    "method": "equals"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00124.json",
            "crime": "Check the current active network type",
            "label": [
                "network"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Object;",
                    "method": "equals",
                    "descriptor": "(Ljava/lang/Object;)Z"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00081.json",
            "crime": "Get declared method from given method name",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "<init>",
                    "descriptor": "()V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00204.json",
            "crime": "Get the default ringtone",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00187.json",
            "crime": "Query a URI and check the result",
            "label": [
                "collection",
                "sms",
                "calllog",
                "calendar"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "moveToNext",
                    "descriptor": "()Z"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "moveToNext",
                    "descriptor": "()Z"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00184.json",
            "crime": "Set camera preview texture",
            "label": [
                "camera"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Object;",
                    "method": "<init>",
                    "descriptor": "()V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00122.json",
            "crime": "Check if the sender address of SMS contains the given string",
            "label": [
                "sms",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/String;",
                    "method": "contains",
                    "descriptor": "(Ljava/lang/CharSequence;)Z"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00008.json",
            "crime": "Check if successfully sending out SMS",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Boolean;",
                    "method": "valueOf",
                    "descriptor": "(Z)Ljava/lang/Boolean;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00175.json",
            "crime": "Get notification manager and cancel notifications ",
            "label": [
                "notification"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00135.json",
            "crime": "Get the current WiFi id and put it into JSON.",
            "label": [
                "wifi",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00025.json",
            "crime": "Monitor the general action to be performed",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Intent;",
                    "method": "getAction",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Ljava/lang/String;",
                    "method": "equals",
                    "descriptor": "(Ljava/lang/Object;)Z"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/Intent;",
                    "method": "getAction",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Ljava/lang/String;",
                    "method": "equals",
                    "descriptor": "(Ljava/lang/Object;)Z"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/eb; onReceive (Landroid/content/Context; Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual",
                            "v4",
                            "Landroid/content/Intent;->getAction()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 83 00 04 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Ljava/lang/String;->equals(Ljava/lang/Object;)Z"
                        ],
                        "second_hex": "6e 20 3e 26 10 00"
                    }
                },
                {
                    "Lcom/google/b/a/a/u; onReceive (Landroid/content/Context; Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual",
                            "v4",
                            "Landroid/content/Intent;->getAction()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 83 00 04 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Ljava/lang/String;->equals(Ljava/lang/Object;)Z"
                        ],
                        "second_hex": "6e 20 3e 26 01 00"
                    }
                },
                {
                    "Lcom/b/a/v; onReceive (Landroid/content/Context; Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual",
                            "v5",
                            "Landroid/content/Intent;->getAction()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 83 00 05 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Ljava/lang/String;->equals(Ljava/lang/Object;)Z"
                        ],
                        "second_hex": "6e 20 3e 26 01 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/google/android/gms/internal/eb; onReceive (Landroid/content/Context; Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual",
                            "v4",
                            "Landroid/content/Intent;->getAction()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 83 00 04 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Ljava/lang/String;->equals(Ljava/lang/Object;)Z"
                        ],
                        "second_hex": "6e 20 3e 26 10 00"
                    }
                },
                {
                    "Lcom/google/b/a/a/u; onReceive (Landroid/content/Context; Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual",
                            "v4",
                            "Landroid/content/Intent;->getAction()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 83 00 04 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Ljava/lang/String;->equals(Ljava/lang/Object;)Z"
                        ],
                        "second_hex": "6e 20 3e 26 01 00"
                    }
                },
                {
                    "Lcom/b/a/v; onReceive (Landroid/content/Context; Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual",
                            "v5",
                            "Landroid/content/Intent;->getAction()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 83 00 05 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Ljava/lang/String;->equals(Ljava/lang/Object;)Z"
                        ],
                        "second_hex": "6e 20 3e 26 01 00"
                    }
                }
            ]
        },
        {
            "rule": "00094.json",
            "crime": "Connect to a URL and read data from it",
            "label": [
                "command",
                "network"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/net/URL;",
                    "method": "openConnection",
                    "descriptor": "()Ljava/net/URLConnection;"
                },
                {
                    "class": "Ljava/io/InputStream;",
                    "method": "read",
                    "descriptor": "([B)I"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Ljava/net/URLConnection;",
                    "class": "Ljava/net/URL;",
                    "method": "openConnection"
                },
                {
                    "descriptor": "([B)I",
                    "class": "Ljava/io/InputStream;",
                    "method": "read"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00010.json",
            "crime": "Read sensitive data(SMS, CALLLOG) and put it into JSON object",
            "label": [
                "sms",
                "calllog",
                "collection"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00074.json",
            "crime": "Get IMSI and the ISO country code",
            "label": [
                "collection",
                "telephony"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00053.json",
            "crime": "Monitor data identified by a given content URI changes(SMS, MMS, etc.)",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00203.json",
            "crime": "Put a phone number into an intent",
            "label": [
                "control"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/Intent;",
                    "method": "setData",
                    "descriptor": "(Landroid/net/Uri;)Landroid/content/Intent;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/Intent;",
                    "method": "setData",
                    "descriptor": "(Landroid/net/Uri;)Landroid/content/Intent;",
                    "match_keywords": [
                        "tel:"
                    ]
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonDiverCaraFotoStudio (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizBanderas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal5 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosFun (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosAmigos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionCollageOpcion (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosSanValentin (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal4 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLocalCars (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLocalChistes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal1 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesDosTres (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionIlusionesOpticas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; e ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosUno (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcoFotosFutbolDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveFunMontages2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionIlusionesOpticas2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosDisfraces (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosIncreibles2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPhotoCollageEditor2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizGeografia (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFunLoveFrames (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonLoveTesterMatchCalculator (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveFun2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionOldMontajes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosInf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoMontajesBillboard (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPersonalPostCards (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/bl; a (Landroid/content/Context; Lcom/google/android/gms/internal/bn; Lcom/google/android/gms/internal/bz;)Z": {
                        "first": [
                            "invoke-static",
                            "v3",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 03 00",
                        "second": [
                            "invoke-virtual",
                            "v2",
                            "v3",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 32 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonTourismSimulator (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; b ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/ge; c (Ljava/lang/String;)Landroid/content/Intent;": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 01 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionTarjetas (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonFunPhotoCollageStudio (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosSV3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonBillboardDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesEsp (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistes (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; b ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionYourPersonalLovePostCardAPP (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFraProf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesEsp2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal9 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFrasesAmistad2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizFootballMund (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetasAmor2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal10 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionLoveTest (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFraAmis (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosIncreibles (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizCoches (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFotosDos (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionPhotoCollageEditor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionTarjetasAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizFutbol (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonFunBackgroundChanger (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonMagicCamera (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoMontajesSanValen2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosFutbol (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotoWarp (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionLocal7 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMontajesFunGentleman (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFramesAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; e ()V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal6 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonCollageMaker (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionFraProf (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFotosKids3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionMarcosInf2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFunnyFaceYou (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonPIP2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionTarjetasAmor (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionFraAmis (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizLocal3 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonRealLovePhotoFrame (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionChistesBrasil (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 00 00",
                        "second": [
                            "invoke-virtual",
                            "v6",
                            "v0",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 06 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; metodoBotonOpcionQuizLocal2 (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/a/a; metodoBotonOpcionQuizBrasil (Landroid/view/View;)V": {
                        "first": [
                            "invoke-static",
                            "v1",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 01 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"
                        ],
                        "second_hex": "6e 20 92 00 10 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00144.json",
            "crime": "Write SIM card serial number into a file",
            "label": [
                "collection",
                "telephony",
                "file",
                "command"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write",
                    "descriptor": "([B)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00090.json",
            "crime": "Set recroded audio/video file format",
            "label": [
                "record"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00102.json",
            "crime": "Set the phone speaker on",
            "label": [
                "command"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00142.json",
            "crime": "Get calendar information",
            "label": [
                "collection",
                "calendar"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "append",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/StringBuilder;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00169.json",
            "crime": "Use accessibility service to perform global action getting node info by View Id",
            "label": [
                "accessibility service"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00128.json",
            "crime": "Query user account information",
            "label": [
                "collection",
                "account"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00159.json",
            "crime": "Use accessibility service to perform action getting node info by text",
            "label": [
                "accessibility service"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00019.json",
            "crime": "Find a method from given class name, usually for reflection",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Object;",
                    "method": "getClass",
                    "descriptor": "()Ljava/lang/Class;"
                },
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getMethod",
                    "descriptor": "(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/lang/Object;",
                    "method": "getClass",
                    "descriptor": "()Ljava/lang/Class;"
                },
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getMethod",
                    "descriptor": "(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/kp; a (Ljava/lang/String; Ljava/lang/Object; Ljava/lang/StringBuffer; Ljava/lang/StringBuffer;)V": {
                        "first": [
                            "invoke-virtual",
                            "v12",
                            "Ljava/lang/Object;->getClass()Ljava/lang/Class;"
                        ],
                        "first_hex": "6e 10 25 26 0c 00",
                        "second": [
                            "invoke-virtual",
                            "v5",
                            "v0",
                            "v8",
                            "Ljava/lang/Class;->getMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "second_hex": "6e 30 d6 25 05 08"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/fb; b (Lcom/google/android/gms/internal/fb$a;)Ljava/lang/Object;": {
                        "first": [
                            "invoke-virtual",
                            "v4",
                            "Ljava/lang/Object;->getClass()Ljava/lang/Class;"
                        ],
                        "first_hex": "6e 10 25 26 04 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "v2",
                            "Ljava/lang/Class;->getMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "second_hex": "6e 30 d6 25 01 02"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/google/android/gms/internal/kp; a (Ljava/lang/String; Ljava/lang/Object; Ljava/lang/StringBuffer; Ljava/lang/StringBuffer;)V": {
                        "first": [
                            "invoke-virtual",
                            "v12",
                            "Ljava/lang/Object;->getClass()Ljava/lang/Class;"
                        ],
                        "first_hex": "6e 10 25 26 0c 00",
                        "second": [
                            "invoke-virtual",
                            "v5",
                            "v0",
                            "v8",
                            "Ljava/lang/Class;->getMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "second_hex": "6e 30 d6 25 05 08"
                    }
                },
                {
                    "Lcom/google/android/gms/internal/fb; b (Lcom/google/android/gms/internal/fb$a;)Ljava/lang/Object;": {
                        "first": [
                            "invoke-virtual",
                            "v4",
                            "Ljava/lang/Object;->getClass()Ljava/lang/Class;"
                        ],
                        "first_hex": "6e 10 25 26 04 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v0",
                            "v2",
                            "Ljava/lang/Class;->getMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                        ],
                        "second_hex": "6e 30 d6 25 01 02"
                    }
                }
            ]
        },
        {
            "rule": "00018.json",
            "crime": "Get JSON object prepared and fill in location info",
            "label": [
                "location",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "<init>",
                    "descriptor": "()V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00112.json",
            "crime": "Get the date of the calendar event",
            "label": [
                "collection",
                "calendar"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00068.json",
            "crime": "Executes the specified string Linux command",
            "label": [
                "control"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00134.json",
            "crime": "Get the current WiFi IP address",
            "label": [
                "wifi",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00113.json",
            "crime": "Get location and put it into JSON",
            "label": [
                "collection",
                "location"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00147.json",
            "crime": "Get the time of current location",
            "label": [
                "collection",
                "location"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/location/Location;",
                    "method": "getTime",
                    "descriptor": "()J"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00079.json",
            "crime": "Hide the current app's icon",
            "label": [
                "evasion"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getPackageManager",
                    "descriptor": "()Landroid/content/pm/PackageManager;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00186.json",
            "crime": "Control camera to take picture",
            "label": [
                "camera"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Object;",
                    "method": "<init>",
                    "descriptor": "()V"
                },
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "takePicture",
                    "descriptor": "(Landroid/hardware/Camera$ShutterCallback; Landroid/hardware/Camera$PictureCallback; Landroid/hardware/Camera$PictureCallback;)V"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/lang/Object;",
                    "method": "<init>",
                    "descriptor": "()V"
                },
                {
                    "class": "Landroid/hardware/Camera;",
                    "method": "takePicture",
                    "descriptor": "(Landroid/hardware/Camera$ShutterCallback; Landroid/hardware/Camera$PictureCallback; Landroid/hardware/Camera$PictureCallback;)V"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00050.json",
            "crime": "Query the SMS service centre timestamp",
            "label": [
                "sms",
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00209.json",
            "crime": "Get pixels from the latest rendered image",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00149.json",
            "crime": "Unpack an asset, possibly decrypt it and load it as DEX",
            "label": [
                "packer"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ldalvik/system/DexClassLoader;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Ljava/lang/ClassLoader;)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00011.json",
            "crime": "Query data from URI (SMS, CALLLOGS)",
            "label": [
                "sms",
                "calllog",
                "collection"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                },
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; a (Landroid/content/Context; Landroid/net/Uri;)Ljava/lang/String;": {
                        "first": [
                            "invoke-static",
                            "v2",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 02 00",
                        "second": [
                            "invoke-static",
                            "v6",
                            "v7",
                            "v0",
                            "v0",
                            "Lcom/pro/lib/libreriafotografia/b;->a(Landroid/content/Context; Landroid/net/Uri; Ljava/lang/String; [Ljava/lang/String;)Ljava/lang/String;"
                        ],
                        "second_hex": "71 40 24 23 76 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; a (Landroid/content/Context; Landroid/net/Uri;)Ljava/lang/String;": {
                        "first": [
                            "invoke-static",
                            "v2",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "first_hex": "71 10 cc 01 02 00",
                        "second": [
                            "invoke-static",
                            "v6",
                            "v7",
                            "v0",
                            "v0",
                            "Lcom/pro/lib/libreriafotografia/b;->a(Landroid/content/Context; Landroid/net/Uri; Ljava/lang/String; [Ljava/lang/String;)Ljava/lang/String;"
                        ],
                        "second_hex": "71 40 24 23 76 00"
                    }
                }
            ]
        },
        {
            "rule": "00044.json",
            "crime": "Query the last time this package's activity was used",
            "label": [
                "collection",
                "reflection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00024.json",
            "crime": "Write file after Base64 decoding",
            "label": [
                "reflection",
                "file"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write",
                    "descriptor": "([B)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00030.json",
            "crime": "Connect to the remote server through the given URL",
            "label": [
                "network"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/net/URL;",
                    "method": "openConnection",
                    "descriptor": "()Ljava/net/URLConnection;"
                },
                {
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "connect",
                    "descriptor": "()V"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/net/URL;",
                    "method": "openConnection",
                    "descriptor": "()Ljava/net/URLConnection;"
                },
                {
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "connect",
                    "descriptor": "()V"
                }
            ],
            "sequence": [
                {
                    "Lcom/google/android/gms/internal/ez; a (Landroid/content/Context; Ljava/lang/String; Ljava/lang/String;)Landroid/webkit/WebResourceResponse;": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->connect()V"
                        ],
                        "second_hex": "6e 10 b0 26 00 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/google/android/gms/internal/ez; a (Landroid/content/Context; Ljava/lang/String; Ljava/lang/String;)Landroid/webkit/WebResourceResponse;": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
                        ],
                        "first_hex": "6e 10 c3 26 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "Ljava/net/HttpURLConnection;->connect()V"
                        ],
                        "second_hex": "6e 10 b0 26 00 00"
                    }
                }
            ]
        },
        {
            "rule": "00193.json",
            "crime": "Send a SMS message",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00133.json",
            "crime": "Start recording",
            "label": [
                "record",
                "command"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00163.json",
            "crime": "Create new Socket and connecting to it",
            "label": [
                "socket"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00188.json",
            "crime": "Get the address of a SMS message",
            "label": [
                "sms"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;",
                    "match_keywords": [
                        "sms"
                    ]
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I",
                    "match_keywords": [
                        "address"
                    ]
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; onActivityResult (I I Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual/range",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "v6",
                            "v7",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "first_hex": "74 06 57 00 02 00",
                        "second": [
                            "invoke-interface",
                            "v3",
                            "v0",
                            "Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I"
                        ],
                        "second_hex": "72 20 d9 00 03 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00056.json",
            "crime": "Modify voice volume",
            "label": [
                "control"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00091.json",
            "crime": "Retrieve data from broadcast",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Intent;",
                    "method": "getExtras",
                    "descriptor": "()Landroid/os/Bundle;"
                },
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Landroid/os/Bundle;",
                    "class": "Landroid/content/Intent;",
                    "method": "getExtras"
                },
                {
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;",
                    "class": "Landroid/os/Bundle;",
                    "method": "getString"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/ligreriagaleriafolderpicasso/MainLibreriaGaleriaFolderPicassoFullScreen; onCreate (Landroid/os/Bundle;)V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/content/Intent;->getExtras()Landroid/os/Bundle;"
                        ],
                        "first_hex": "6e 10 87 00 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;"
                        ],
                        "second_hex": "6e 20 21 02 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriagraficos/renovado/LibreriaEfectosGraficosRenovado; onCreate (Landroid/os/Bundle;)V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/content/Intent;->getExtras()Landroid/os/Bundle;"
                        ],
                        "first_hex": "6e 10 87 00 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;"
                        ],
                        "second_hex": "6e 20 21 02 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; onActivityResult (I I Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual",
                            "v15",
                            "Landroid/content/Intent;->getExtras()Landroid/os/Bundle;"
                        ],
                        "first_hex": "6e 10 87 00 0f 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v2",
                            "Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;"
                        ],
                        "second_hex": "6e 20 21 02 21 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/pro/lib/ligreriagaleriafolderpicasso/MainLibreriaGaleriaFolderPicassoFullScreen; onCreate (Landroid/os/Bundle;)V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/content/Intent;->getExtras()Landroid/os/Bundle;"
                        ],
                        "first_hex": "6e 10 87 00 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;"
                        ],
                        "second_hex": "6e 20 21 02 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriagraficos/renovado/LibreriaEfectosGraficosRenovado; onCreate (Landroid/os/Bundle;)V": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/content/Intent;->getExtras()Landroid/os/Bundle;"
                        ],
                        "first_hex": "6e 10 87 00 00 00",
                        "second": [
                            "invoke-virtual",
                            "v0",
                            "v1",
                            "Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;"
                        ],
                        "second_hex": "6e 20 21 02 10 00"
                    }
                },
                {
                    "Lcom/pro/lib/libreriafotografia/b; onActivityResult (I I Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual",
                            "v15",
                            "Landroid/content/Intent;->getExtras()Landroid/os/Bundle;"
                        ],
                        "first_hex": "6e 10 87 00 0f 00",
                        "second": [
                            "invoke-virtual",
                            "v1",
                            "v2",
                            "Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;"
                        ],
                        "second_hex": "6e 20 21 02 21 00"
                    }
                }
            ]
        },
        {
            "rule": "00174.json",
            "crime": "Get all accounts by type and put them in a JSON object",
            "label": [
                "accounts",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00101.json",
            "crime": "Initialize recorder",
            "label": [
                "record"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00115.json",
            "crime": "Get last known location of the device",
            "label": [
                "collection",
                "location"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/location/Location;",
                    "method": "getLongitude",
                    "descriptor": "()D"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00047.json",
            "crime": "Query the local IP address",
            "label": [
                "network",
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00155.json",
            "crime": "Execute commands on shell using DataOutputStream object",
            "label": [
                "exec",
                "command"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00130.json",
            "crime": "Get the current WIFI information",
            "label": [
                "wifi",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00177.json",
            "crime": "Check if permission is granted and request it",
            "label": [
                "permission"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00058.json",
            "crime": "Connect to the specific WIFI network",
            "label": [
                "wifi",
                "control"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00001.json",
            "crime": "Initialize bitmap object and compress data (e.g. JPEG) into bitmap object",
            "label": [
                "camera"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/graphics/BitmapFactory;",
                    "method": "decodeByteArray",
                    "descriptor": "([B I I)Landroid/graphics/Bitmap;"
                },
                {
                    "class": "Landroid/graphics/Bitmap;",
                    "method": "compress",
                    "descriptor": "(Landroid/graphics/Bitmap$CompressFormat; I Ljava/io/OutputStream;)Z"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/graphics/BitmapFactory;",
                    "method": "decodeByteArray",
                    "descriptor": "([B I I)Landroid/graphics/Bitmap;"
                },
                {
                    "class": "Landroid/graphics/Bitmap;",
                    "method": "compress",
                    "descriptor": "(Landroid/graphics/Bitmap$CompressFormat; I Ljava/io/OutputStream;)Z"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00069.json",
            "crime": "Run shell script programmably",
            "label": [
                "control"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00060.json",
            "crime": "Query the network operator name",
            "label": [
                "network",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Integer;",
                    "method": "valueOf",
                    "descriptor": "(I)Ljava/lang/Integer;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00200.json",
            "crime": "Query data from the contact list",
            "label": [
                "collection",
                "contact"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;",
                    "match_keywords": [
                        "Phone"
                    ]
                },
                {
                    "class": "Landroid/database/Cursor;",
                    "method": "getColumnIndex",
                    "descriptor": "(Ljava/lang/String;)I"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; onActivityResult (I I Landroid/content/Intent;)V": {
                        "first": [
                            "invoke-virtual/range",
                            "v2",
                            "v3",
                            "v4",
                            "v5",
                            "v6",
                            "v7",
                            "Landroid/content/ContentResolver;->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                        ],
                        "first_hex": "74 06 57 00 02 00",
                        "second": [
                            "invoke-interface",
                            "v3",
                            "v0",
                            "Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I"
                        ],
                        "second_hex": "72 20 d9 00 03 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00119.json",
            "crime": "Write the IMEI number into a file",
            "label": [
                "collection",
                "file",
                "telephony",
                "command"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write",
                    "descriptor": "([B)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00141.json",
            "crime": "Load class from given class name",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "toString",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Ljava/lang/ClassLoader;",
                    "method": "loadClass",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Ljava/lang/String;",
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "toString"
                },
                {
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;",
                    "class": "Ljava/lang/ClassLoader;",
                    "method": "loadClass"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00154.json",
            "crime": "Connect hostname to TCP or UDP socket using KryoNet",
            "label": [
                "socket"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/net/InetAddress;",
                    "method": "getByName",
                    "descriptor": "(Ljava/lang/String;)Ljava/net/InetAddress;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00073.json",
            "crime": "Write the SIM card information into a file",
            "label": [
                "collection",
                "telephony",
                "file"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/FileOutputStream;",
                    "method": "write",
                    "descriptor": "([B)V"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00117.json",
            "crime": "Get the IMSI and network operator name",
            "label": [
                "telephony",
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00085.json",
            "crime": "Get the ISO country code and put it into JSON",
            "label": [
                "collection",
                "telephony"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00143.json",
            "crime": "Get external class from given path or file name",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/StringBuilder;",
                    "method": "toString",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00029.json",
            "crime": "Initialize class object dynamically",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Class;",
                    "method": "forName",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00123.json",
            "crime": "Save the response to JSON after connecting to the remote server",
            "label": [
                "network",
                "command"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "connect",
                    "descriptor": "()V"
                },
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String;)V"
                }
            ],
            "combination": [
                {
                    "descriptor": "()V",
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "connect"
                },
                {
                    "descriptor": "(Ljava/lang/String;)V",
                    "class": "Lorg/json/JSONObject;",
                    "method": "<init>"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00108.json",
            "crime": "Read the input stream from given URL",
            "label": [
                "network",
                "command"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "getInputStream",
                    "descriptor": "()Ljava/io/InputStream;"
                },
                {
                    "class": "Ljava/io/InputStream;",
                    "method": "read",
                    "descriptor": "([B)I"
                }
            ],
            "combination": [
                {
                    "descriptor": "()Ljava/io/InputStream;",
                    "class": "Ljava/net/HttpURLConnection;",
                    "method": "getInputStream"
                },
                {
                    "descriptor": "([B)I",
                    "class": "Ljava/io/InputStream;",
                    "method": "read"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00196.json",
            "crime": "Set the recorded file format and output path",
            "label": [
                "record",
                "file"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00125.json",
            "crime": "Check if the given file path exist",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                },
                {
                    "class": "Ljava/io/File;",
                    "method": "exists",
                    "descriptor": "()Z"
                }
            ],
            "combination": [
                {
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;",
                    "class": "Landroid/os/Bundle;",
                    "method": "getString"
                },
                {
                    "descriptor": "()Z",
                    "class": "Ljava/io/File;",
                    "method": "exists"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00013.json",
            "crime": "Read file and put it into a stream",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 1.0,
            "confidence": "100%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/io/File;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String;)V"
                },
                {
                    "class": "Ljava/io/FileInputStream;",
                    "method": "<init>",
                    "descriptor": "(Ljava/io/File;)V"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/io/File;",
                    "method": "<init>",
                    "descriptor": "(Ljava/lang/String;)V"
                },
                {
                    "class": "Ljava/io/FileInputStream;",
                    "method": "<init>",
                    "descriptor": "(Ljava/io/File;)V"
                }
            ],
            "sequence": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; a (Ljava/lang/String; I I)Landroid/graphics/Bitmap;": {
                        "first": [
                            "invoke-direct",
                            "v3",
                            "v6",
                            "Ljava/io/File;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 85 25 63 00",
                        "second": [
                            "invoke-direct",
                            "v1",
                            "v3",
                            "Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V"
                        ],
                        "second_hex": "70 20 91 25 31 00"
                    }
                }
            ],
            "register": [
                {
                    "Lcom/pro/lib/libreriafotografia/b; a (Ljava/lang/String; I I)Landroid/graphics/Bitmap;": {
                        "first": [
                            "invoke-direct",
                            "v3",
                            "v6",
                            "Ljava/io/File;-><init>(Ljava/lang/String;)V"
                        ],
                        "first_hex": "70 20 85 25 63 00",
                        "second": [
                            "invoke-direct",
                            "v1",
                            "v3",
                            "Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V"
                        ],
                        "second_hex": "70 20 91 25 31 00"
                    }
                }
            ]
        },
        {
            "rule": "00080.json",
            "crime": "Save recorded audio/video to a file",
            "label": [
                "record",
                "file"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/os/Bundle;",
                    "method": "getString",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00037.json",
            "crime": "Send notification",
            "label": [
                "control"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00064.json",
            "crime": "Monitor incoming call status",
            "label": [
                "control"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00015.json",
            "crime": "Put buffer stream (data) to JSON object",
            "label": [
                "file"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Lorg/json/JSONObject;",
                    "method": "put",
                    "descriptor": "(Ljava/lang/String; Ljava/lang/Object;)Lorg/json/JSONObject;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00041.json",
            "crime": "Save recorded audio/video to file",
            "label": [
                "record"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00032.json",
            "crime": "Load external class",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getClassLoader",
                    "descriptor": "()Ljava/lang/ClassLoader;"
                },
                {
                    "class": "Ljava/lang/ClassLoader;",
                    "method": "loadClass",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getClassLoader",
                    "descriptor": "()Ljava/lang/ClassLoader;"
                },
                {
                    "class": "Ljava/lang/ClassLoader;",
                    "method": "loadClass",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00205.json",
            "crime": "Simulate a touch gesture on the device screen",
            "label": [
                "accessibility service",
                "control"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00027.json",
            "crime": "Get specific method from other Dex files",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/ClassLoader;",
                    "method": "loadClass",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;"
                },
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getMethod",
                    "descriptor": "(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/lang/ClassLoader;",
                    "method": "loadClass",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;"
                },
                {
                    "class": "Ljava/lang/Class;",
                    "method": "getMethod",
                    "descriptor": "(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00066.json",
            "crime": "Query the ICCID number",
            "label": [
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00055.json",
            "crime": "Query the SMS content and the source of the phone number",
            "label": [
                "sms",
                "collection"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00036.json",
            "crime": "Get resource file from res/raw directory",
            "label": [
                "reflection"
            ],
            "score": 1,
            "weight": 0.5,
            "confidence": "80%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getPackageName",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                }
            ],
            "combination": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getPackageName",
                    "descriptor": "()Ljava/lang/String;"
                },
                {
                    "class": "Landroid/net/Uri;",
                    "method": "parse",
                    "descriptor": "(Ljava/lang/String;)Landroid/net/Uri;"
                }
            ],
            "sequence": [
                {
                    "Landroid/support/v7/widget/e; a (Ljava/lang/String;)Landroid/graphics/drawable/Drawable;": {
                        "first": [
                            "invoke-virtual",
                            "v3",
                            "Landroid/content/Context;->getPackageName()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 6e 00 03 00",
                        "second": [
                            "invoke-static",
                            "v5",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "second_hex": "71 10 cc 01 05 00"
                    }
                },
                {
                    "Lcom/pro/lib/ligreriagaleriafolderpicasso/j; a ()[Ljava/lang/String;": {
                        "first": [
                            "invoke-virtual",
                            "v0",
                            "Landroid/content/Context;->getPackageName()Ljava/lang/String;"
                        ],
                        "first_hex": "6e 10 6e 00 00 00",
                        "second": [
                            "invoke-static",
                            "v0",
                            "Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;"
                        ],
                        "second_hex": "71 10 cc 01 00 00"
                    }
                }
            ],
            "register": []
        },
        {
            "rule": "00166.json",
            "crime": "Get SMS message body and retrieve a string from it (possibly PIN / mTAN)",
            "label": [
                "sms",
                "pin"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00179.json",
            "crime": "Send Location via SMS",
            "label": [
                "location",
                "collection"
            ],
            "score": 1,
            "weight": 0,
            "confidence": "0%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00088.json",
            "crime": "Create a secure socket connection to the given host address",
            "label": [
                "command",
                "network"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00083.json",
            "crime": "Query the IMEI number",
            "label": [
                "collection",
                "telephony"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00003.json",
            "crime": "Put the compressed bitmap data into JSON object",
            "label": [
                "camera"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/graphics/Bitmap;",
                    "method": "compress",
                    "descriptor": "(Landroid/graphics/Bitmap$CompressFormat; I Ljava/io/OutputStream;)Z"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00180.json",
            "crime": "Load native libraries(.so) via System.loadLibrary (60% means caught)",
            "label": [
                "so"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Ljava/lang/System;",
                    "method": "loadLibrary",
                    "descriptor": "(Ljava/lang/String;)V"
                },
                {
                    "class": "Ljava/lang/System;",
                    "method": "loadLibrary",
                    "descriptor": "(Ljava/lang/String;)V"
                }
            ],
            "combination": [
                {
                    "class": "Ljava/lang/System;",
                    "method": "loadLibrary",
                    "descriptor": "(Ljava/lang/String;)V"
                },
                {
                    "class": "Ljava/lang/System;",
                    "method": "loadLibrary",
                    "descriptor": "(Ljava/lang/String;)V"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00126.json",
            "crime": "Read sensitive data(SMS, CALLLOG, etc)",
            "label": [
                "collection",
                "sms",
                "calllog",
                "calendar"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query",
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
                },
                {
                    "class": "Ljava/lang/String;",
                    "method": "toString",
                    "descriptor": "()Ljava/lang/String;"
                }
            ],
            "combination": [
                {
                    "descriptor": "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;",
                    "class": "Landroid/content/ContentResolver;",
                    "method": "query"
                },
                {
                    "descriptor": "()Ljava/lang/String;",
                    "class": "Ljava/lang/String;",
                    "method": "toString"
                }
            ],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00132.json",
            "crime": "Query The ISO country code",
            "label": [
                "telephony",
                "collection"
            ],
            "score": 1,
            "weight": 0.125,
            "confidence": "40%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/content/Context;",
                    "method": "getSystemService",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/Object;"
                }
            ],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00148.json",
            "crime": "Create a socket connection to the given host address",
            "label": [
                "network",
                "command"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00093.json",
            "crime": "Get the content of SMS and forward it to others via SMS",
            "label": [
                "collection",
                "sms",
                "command"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00039.json",
            "crime": "Start a web server",
            "label": [
                "control",
                "network"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00161.json",
            "crime": "Perfom accessibility service action on accessibility node info",
            "label": [
                "accessibility service"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00194.json",
            "crime": "Set the audio source (MIC) and recorded file format",
            "label": [
                "record"
            ],
            "score": 1,
            "weight": 0.0625,
            "confidence": "20%",
            "permissions": [],
            "native_api": [],
            "combination": [],
            "sequence": [],
            "register": []
        },
        {
            "rule": "00087.json",
            "crime": "Check the current network type",
            "label": [
                "network"
            ],
            "score": 1,
            "weight": 0.25,
            "confidence": "60%",
            "permissions": [],
            "native_api": [
                {
                    "class": "Landroid/net/NetworkInfo;",
                    "method": "getType",
                    "descriptor": "()I"
                },
                {
                    "class": "Ljava/lang/Object;",
                    "method": "equals",
                    "descriptor": "(Ljava/lang/Object;)Z"
                }
            ],
            "combination": [
                {
                    "descriptor": "()I",
                    "class": "Landroid/net/NetworkInfo;",
                    "method": "getType"
                },
                {
                    "descriptor": "(Ljava/lang/Object;)Z",
                    "class": "Ljava/lang/Object;",
                    "method": "equals"
                }
            ],
            "sequence": [],
            "register": []
        }
    ]
}"""

import re
from pprint import pprint
from utility import load_json_path_repair
enc = tiktoken.get_encoding("o200k_base")
print(len(enc.encode(re.sub(r'\s+', '', file))))

from pathlib import Path
file2 = Path('/shared/frankzha/data/datasets/oddity/fst_time_benign/252245a025f166632e65e23ee3342586.json')

def find_key_with_path(obj, key_to_find, current_path=[]):
    """
    Recursively searches for a key and returns its value along with the
    full path to access it.

    Args:
        obj: The dictionary or list to search.
        key_to_find: The key to search for.
        current_path: A list used internally by the recursion to track the path.

    Returns:
        A tuple containing (path_string, value) if the key is found.
        (None, None) if the key is not found.
    """
    # If the object is a dictionary, search its keys and values
    if isinstance(obj, dict):
        if key_to_find in obj:
            # --- KEY FOUND! ---
            # Create the final path list
            final_path = current_path + [key_to_find]
            # Format the path list into a readable string like 'obj[key][index]'
            path_str = "json_obj" + "".join(
                [f"['{k}']" if isinstance(k, str) else f"[{k}]" for k in final_path]
            )
            return (path_str, obj[key_to_find])

        # If key not found at this level, recurse into the dictionary's values
        for key, value in obj.items():
            path, found_value = find_key_with_path(value, key_to_find, current_path + [key])
            if path:  # If a path was returned from the recursive call, we are done
                return (path, found_value)

    # If the object is a list, recurse into its items
    elif isinstance(obj, list):
        for index, item in enumerate(obj):
            path, found_value = find_key_with_path(item, key_to_find, current_path + [index])
            if path:  # If a path was returned, we are done
                return (path, found_value)

    # If we've searched everything and found nothing, return None for both
    return (None, None)


import json
json_obj = load_json_path_repair(file2)
print("Type of json_obj is:", type(json_obj))
# print(repr(json_obj).strip())
print(json_obj.keys())
print(find_key_with_path(json_obj, 'last_analysis_stats'))
print(json_obj['data']['attributes'].keys())
print(json_obj['data']['attributes']['androguard'].keys())


pprint(json.load(file2.open())['data']['attributes']['last_analysis_stats'])


# attrs = j['data']['attributes']
# print(repr(attrs).strip())
# pprint(attrs['last_analysis_stats'])


# import json, openai, msgspec
# import json_repair as jr

# try:
#     s = json.loads(file)
#     print('end, ', len(s))
# except json.decoder.JSONDecodeError as e:
#     print(e)
#     lines = file.splitlines()
#     for ln in range(e.lineno-5, e.lineno+5):
#         print(f'[{ln}] {lines[ln-1]}')

        
        
# _openai_api_key = ('sk-proj-RX9BCsg16JAzHUzTu2ah5hxVY14L3cDJGqe9I5q2N8LOnxH'
#                    'HhBf7eL8lMuYrcY7QYloWwv73OOT3BlbkFJ34y2jpotTOd5968dwREb'
#                    'rtdPd_hGy8KX4RYJIJOo9un4esUgbOAvWeDs1OxOxZoLGJXELh9_MA')

# client = openai.OpenAI(api_key=_openai_api_key)

# JSON_DECODER = msgspec.json.Decoder(dict)

# def load_json_path(
#     path: Path,
#     counter: Iterator[int] | None = None
# ) -> dict:
#     """
#     If the JSON decoder cannot decode the response, trigger an LLM (GPT 4o-mini) response
#                  to correct the JSON response.
#     """
#     text = re.sub(r'\s+', '', path.read_bytes().decode('utf-8-sig', errors='replace'))
#     try:
#         return JSON_DECODER.decode(text)
#     except msgspec.DecodeError:
#         if counter is not None:
#             next(counter)
#         corrected_text = client.chat.completions.create(
#             model='gpt-4.1-mini',
#             messages=[
#                 {
#                     "role": "system",
#                     "content": (
#                         "You are a JSON linter/fixer. "
#                         "Given a malformed JSON document, "
#                         "make the minimal edits needed so that the result is valid JSON. "
#                         'For each crime in the top-level `crimes` array, remove the keys: '
#                         "`rule`, `crime`, `label`, `native_api`, `combination`, `sequence`, and `register`."
#                         "Do NOT include them in the JSON output; only include `score`, `weight`, and `confidence`. "
#                         "Do NOT add or remove any other data. "
#                         "Make sure that a JSON parser can parse the output. "
#                         "Only output the valid JSON, nothing else. No spaces, tabs, or newlines."
#                     )
#                 },
#                 {
#                     "role": "user",
#                     "content": f"```json\n{text}\n```"
#                 }
#             ],
#             max_completion_tokens=500_000
#         ).choices[0].message.content.strip()
#         return JSON_DECODER.decode(corrected_text)

# text = re.sub(r'\s+', '', file)
# corrected_text = client.chat.completions.create(
#     model='gpt-4.1-mini',
#     messages=[
#         {
#             "role": "system",
#             "content": (
#                 "You are a JSON linter/fixer. "
#                 "Given a malformed JSON document, "
#                 "make the minimal edits needed so that the result is valid JSON. "
#                 'For each crime in the top-level `crimes` array, remove the keys: '
#                 "`rule`, `crime`, `label`, `native_api`, `combination`, `sequence`, and `register`."
#                 "Do NOT include them in the JSON output; only include `score`, `weight`, and `confidence`. "
#                 "Do NOT add or remove any other data. "
#                 "Make sure that a JSON parser can parse the output. "
#                 "Only output the valid JSON, nothing else. No spaces, tabs, or newlines."
#             )
#         },
#         {
#             "role": "user",
#             "content": f"```json\n{text}\n```"
#         }
#     ],
#     # max_completion_tokens=500_000
# ).choices[0].message.content.strip()

# print('a:', len(corrected_text))
# print(corrected_text[:200])
# j = JSON_DECODER.decode(corrected_text)
# print('b:', len(j))
# print(j[:30])