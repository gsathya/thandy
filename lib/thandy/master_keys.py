# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

MASTER_KEYS = [
    {
        "_keytype": "rsa",
        "e": "AQAB",
        "n": "0qZkVHg5yQE6KjIMUFH8lN9gKG8QKXiSuY9uFUXvPd7cNme/9/LpCyXJAEmxtRtqOR/mMudpndpiGlwQySP42lv75Kfmz9bWuZrNKHUW4XocSU/orj8tDcvx1DUb2KPTDxmnSOULtI4phfshBuokQSHCPmM8jB2u+EnsmoY2kf4xbsH9wou6LTTItbAe0ZwsYVB40BCmulRMx84sd+jnV5XJah9oJUoQY2L6l4UtwMQjB4FogWLiZBw+wMFDGVb/+r32c/e1qwi4B6Hxmg8YsipwNgbWS6yYXyBQg4pN4DyOjld5xSbYqTZQuHtWPZN/ttbb0xLwla1JK8/P16f6vQ",
        "roles": [ [ "master", "/meta/keys.txt" ] ]
   }
]

DEFAULT_MIRRORLIST = {
  "mirrors": [ {'name'     :"master repository",
                'urlbase'  :"http://updates.torproject.org/thandy/",
                'contents' : ["/**"],
                'weight'   : 1
                }
             ],
}
