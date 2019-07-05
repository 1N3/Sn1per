#!/bin/bash

SLACK_API_TOKEN=""
SLACK_CHANNEL="sn1per-professional"
MESSAGE="$1"

if [ "$MESSAGE" == "postfile" ]; then
	FILENAME="$2"
	curl -v -F "file=@$FILENAME" "https://slack.com/api/files.upload?token=$SLACK_API_TOKEN&channels=%23$SLACK_CHANNEL&filename=$FILENAME&pretty=1" 2> /dev/null > /dev/null
else
	curl -G --data-urlencode "text=$MESSAGE" \
		--data-urlencode "token=$SLACK_API_TOKEN" \
		--data-urlencode "channel=#$SLACK_CHANNEL" \
		-i -s -k  -X $'GET' \
		-H $'Host: slack.com' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' \
		$'https://slack.com/api/chat.postMessage' 2> /dev/null > /dev/null
fi
