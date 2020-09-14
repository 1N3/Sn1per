#!/bin/bash
# Slack API Integration script for Sn1per
# By @xer0dayz - https://xerosecurity.com
#

source /usr/share/sniper/sniper.conf 2> /dev/null
source /root/.sniper.conf 2> /dev/null
source /root/.sniper_api_keys.conf 2> /dev/null

MESSAGE="$1"

if [ "$MESSAGE" == "postfile" ]; then
	FILENAME="$2"
	curl -F "file=@$FILENAME" -F "initial_comment=$FILENAME" -F "channels=$SLACK_CHANNEL" -H "Authorization: Bearer $SLACK_API_TOKEN" https://slack.com/api/files.upload 2> /dev/null > /dev/null
else
	curl -X POST -H 'Content-type: application/json' --data "{\"text\":\"$MESSAGE\"}" $SLACK_WEBHOOK_URL 2> /dev/null > /dev/null
fi
